#include "subprocess.hpp"
#include <array>
#include <ostream>
#include <string>

#include <qbytearray.h>
#include <qlogging.h>
#include <qloggingcategory.h>
#include <qstring.h>
#include <sched.h>
#ifdef __FreeBSD__
#include <security/pam_types.h>
#else
#include <security/_pam_types.h>
#endif
#include <security/pam_appl.h>
#include <unistd.h>

#include "conversation.hpp"
#include "ipc.hpp"

pid_t PamConversation::createSubprocess(
    PamIpcPipes* pipes,
    const QString& configDir,
    const QString& config,
    const QString& user
) {
	auto toSubprocess = std::array<int, 2>();
	auto fromSubprocess = std::array<int, 2>();

	if (pipe(toSubprocess.data()) == -1) {
		qCDebug(logPam) << "Failed to create pipes for subprocess.";
		return 0;
	}

	auto toSubprocessGuard = PamIpcPipes(toSubprocess[0], toSubprocess[1]);

	if (pipe(fromSubprocess.data()) == -1) {
		qCDebug(logPam) << "Failed to create pipes for subprocess.";
		return 0;
	}

	auto fromSubprocessGuard = PamIpcPipes(fromSubprocess[0], fromSubprocess[1]);
	auto configDirF = configDir.toUtf8();
	auto configF = config.toUtf8();
	auto userF = user.toUtf8();
	auto log = logPam().isDebugEnabled();
	auto pid = fork();

	if (pid < 0) {
		qCDebug(logPam) << "Failed to fork for subprocess.";
		return 0;
	} else if (pid == 0) {
		close(toSubprocessGuard.fdOut);
		close(fromSubprocessGuard.fdIn);

		{
			auto subprocess = PamSubprocess(log, toSubprocessGuard.fdIn, fromSubprocessGuard.fdOut);
			auto code = subprocess.exec(configDirF.constData(), configF.constData(), userF.constData());
			subprocess.sendCode(code);
		}

		// do not do cleanup that may affect the parent
		_exit(0);
	} else {
		close(toSubprocessGuard.fdIn);
		toSubprocessGuard.fdIn = 0;
		close(fromSubprocessGuard.fdOut);
		fromSubprocessGuard.fdOut = 0;

		pipes->fdIn = fromSubprocessGuard.fdIn;
		fromSubprocessGuard.fdIn = 0;
		pipes->fdOut = toSubprocessGuard.fdOut;
		toSubprocessGuard.fdOut = 0;

		return pid;
	}
}

PamIpcExitCode PamSubprocess::exec(const char* configDir, const char* config, const char* user) {
	logIf(this->log) << "Waiting for parent confirmation..." << std::endl;

	auto conv = pam_conv {
	    .conv = &PamSubprocess::conversation,
	    .appdata_ptr = this,
	};

	pam_handle_t* handle = nullptr;

	logIf(this->log) << "Starting pam session for user \"" << user << "\" with config \"" << config
	                 << "\" in dir \"" << configDir << "\"" << std::endl;

#ifdef __FreeBSD__
	auto result = pam_start(config, user, &conv, &handle);
#else
	auto result = pam_start_confdir(config, user, &conv, configDir, &handle);
#endif

	if (result != PAM_SUCCESS) {
		logIf(true) << "Unable to start pam conversation with error \"" << pam_strerror(handle, result)
		            << "\" (code " << result << ")" << std::endl;
		return PamIpcExitCode::StartFailed;
	}

	result = pam_authenticate(handle, 0);
	PamIpcExitCode code = PamIpcExitCode::OtherError;

	switch (result) {
	case PAM_SUCCESS:
		logIf(this->log) << "Authenticated successfully." << std::endl;
		code = PamIpcExitCode::Success;
		break;
	case PAM_AUTH_ERR:
		logIf(this->log) << "Failed to authenticate." << std::endl;
		code = PamIpcExitCode::AuthFailed;
		break;
	case PAM_MAXTRIES:
		logIf(this->log) << "Failed to authenticate due to hitting max tries." << std::endl;
		code = PamIpcExitCode::MaxTries;
		break;
	default:
		logIf(true) << "Error while authenticating: \"" << pam_strerror(handle, result) << "\" (code "
		            << result << ")" << std::endl;
		code = PamIpcExitCode::PamError;
		break;
	}

	result = pam_end(handle, result);
	if (result != PAM_SUCCESS) {
		logIf(true) << "Error in pam_end: \"" << pam_strerror(handle, result) << "\" (code " << result
		            << ")" << std::endl;
	}

	return code;
}

void PamSubprocess::sendCode(PamIpcExitCode code) {
	{
		auto eventType = PamIpcEvent::Exit;
		auto ok = this->pipes.writeBytes(reinterpret_cast<char*>(&eventType), sizeof(PamIpcEvent));

		if (!ok) goto fail;

		ok = this->pipes.writeBytes(reinterpret_cast<char*>(&code), sizeof(PamIpcExitCode));

		if (!ok) goto fail;

		return;
	}

fail:
	_exit(1);
}

int PamSubprocess::conversation(
    int msgCount,
    const pam_message** msgArray,
    pam_response** responseArray,
    void* appdata
) {
	auto* delegate = static_cast<PamSubprocess*>(appdata);

	// freed by libc so must be alloc'd by it.
	auto* responses = static_cast<pam_response*>(calloc(msgCount, sizeof(pam_response))); // NOLINT

	for (auto i = 0; i < msgCount; i++) {
		const auto* message = msgArray[i]; // NOLINT
		auto& response = responses[i];     // NOLINT

		auto msgString = std::string(message->msg);
		auto req = PamIpcRequestFlags {
		    .echo = message->msg_style != PAM_PROMPT_ECHO_OFF,
		    .error = message->msg_style == PAM_ERROR_MSG,
		    .responseRequired =
		        message->msg_style == PAM_PROMPT_ECHO_OFF || message->msg_style == PAM_PROMPT_ECHO_ON,
		};

		logIf(delegate->log) << "Relaying pam message: \"" << msgString << "\" echo: " << req.echo
		                     << " error: " << req.error << " responseRequired: " << req.responseRequired
		                     << std::endl;

		auto eventType = PamIpcEvent::Request;
		auto ok = delegate->pipes.writeBytes(reinterpret_cast<char*>(&eventType), sizeof(PamIpcEvent));

		if (!ok) goto fail;

		ok =
		    delegate->pipes.writeBytes(reinterpret_cast<const char*>(&req), sizeof(PamIpcRequestFlags));

		if (!ok) goto fail;
		if (!delegate->pipes.writeString(msgString)) goto fail;

		if (req.responseRequired) {
			auto ok = false;
			auto resp = delegate->pipes.readString(&ok);
			if (!ok) _exit(static_cast<int>(PamIpcExitCode::OtherError));
			logIf(delegate->log) << "Got response for request.";

			response.resp = strdup(resp.c_str()); // NOLINT (include)
		}
	}

	*responseArray = responses;
	return PAM_SUCCESS;

fail:
	free(responses); // NOLINT
	_exit(1);
}
