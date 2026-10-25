//SPDX-License-Identifier: GPL-2.0-or-later

#include "varlink-org.openSUSE.cap-grant.h"

static SD_VARLINK_DEFINE_METHOD(
		SetPriority,
		SD_VARLINK_FIELD_COMMENT("Request new nice priority"),
		SD_VARLINK_DEFINE_INPUT(Priority, SD_VARLINK_INT,  0),
		SD_VARLINK_DEFINE_OUTPUT(Success, SD_VARLINK_BOOL, 0),
		SD_VARLINK_DEFINE_OUTPUT(ErrorMsg, SD_VARLINK_STRING, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
		Quit,
		SD_VARLINK_FIELD_COMMENT("Stop the daemon"),
		SD_VARLINK_DEFINE_INPUT(ExitCode, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
		SD_VARLINK_DEFINE_OUTPUT(Success, SD_VARLINK_BOOL, 0));

static SD_VARLINK_DEFINE_METHOD(
		Ping,
		SD_VARLINK_FIELD_COMMENT("Check if service is alive"),
		SD_VARLINK_DEFINE_OUTPUT(Alive, SD_VARLINK_BOOL, 0));

static SD_VARLINK_DEFINE_METHOD(
                SetLogLevel,
                SD_VARLINK_FIELD_COMMENT("The maximum log level, using BSD syslog log level integers."),
                SD_VARLINK_DEFINE_INPUT(Level, SD_VARLINK_INT, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
		Socket,
		SD_VARLINK_FIELD_COMMENT("Open a socket and pass back its file descriptor"),
		SD_VARLINK_DEFINE_INPUT(Domain, SD_VARLINK_INT, 0),
		SD_VARLINK_DEFINE_INPUT(Type, SD_VARLINK_INT, 0),
		SD_VARLINK_DEFINE_INPUT(Protocol, SD_VARLINK_INT, 0),
		SD_VARLINK_DEFINE_OUTPUT(Success, SD_VARLINK_BOOL, 0),
		SD_VARLINK_DEFINE_OUTPUT(ErrorMsg, SD_VARLINK_STRING, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_ERROR(InternalError);

SD_VARLINK_DEFINE_INTERFACE(
                org_openSUSE_CapGrant,
                "org.openSUSE.CapGrant",
		SD_VARLINK_INTERFACE_COMMENT("Cap-grantd control APIs"),
		SD_VARLINK_SYMBOL_COMMENT("Set new process priority"),
                &vl_method_SetPriority,
 		SD_VARLINK_SYMBOL_COMMENT("Stop the daemon"),
                &vl_method_Quit,
		SD_VARLINK_SYMBOL_COMMENT("Checks if the service is running."),
                &vl_method_Ping,
                SD_VARLINK_SYMBOL_COMMENT("Sets the maximum log level."),
                &vl_method_SetLogLevel,
		SD_VARLINK_SYMBOL_COMMENT("Open a socket and pass back its file descriptor"),
		&vl_method_Socket,
		SD_VARLINK_SYMBOL_COMMENT("Internal Error"),
		&vl_error_InternalError);
