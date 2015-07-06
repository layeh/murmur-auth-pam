/* Copyright (C) 2015, Tim Cooper <tim.cooper@layeh.com>

   All rights reserved.

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions
   are met:

   - Redistributions of source code must retain the above copyright notice,
     this list of conditions and the following disclaimer.
   - Redistributions in binary form must reproduce the above copyright notice,
     this list of conditions and the following disclaimer in the documentation
     and/or other materials provided with the distribution.
   - Neither the name of the Mumble Developers nor the names of its
     contributors may be used to endorse or promote products derived from this
     software without specific prior written permission.

   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
   ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
   A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR
   CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
   EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
   PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
   PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
   LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
   NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
   SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <iostream>
#include <cstdlib>
#include <cstring>

#define BOOST_LOG_DYN_LINK 1
#include <boost/log/trivial.hpp>

#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <security/pam_appl.h>

#include <grpc/grpc.h>
#include <grpc++/channel_arguments.h>
#include <grpc++/client_context.h>
#include <grpc++/create_channel.h>
#include <grpc++/credentials.h>

#include "MurmurRPC/MurmurRPC.grpc.pb.h"

#define SERVICE_NAME "murmur-auth-pam"

bool valid_user(const MurmurRPC::Authenticator_Request &req, MurmurRPC::Authenticator_Response &resp);

int main(int argc, char *argv[]) {
	if (argc <= 1) {
		std::cerr << "usage: " << argv[0] << " <server IP and port>" << std::endl;
		return 1;
	}

	auto channel = grpc::CreateChannel(argv[1], grpc::InsecureCredentials(), grpc::ChannelArguments());
	grpc::ClientContext ctx;
	auto stub = MurmurRPC::AuthenticatorService::NewStub(channel);

	BOOST_LOG_TRIVIAL(info) << "Starting murmur-auth-pam";

	auto stream = stub->Stream(&ctx);

	MurmurRPC::Authenticator_Response init;
	init.mutable_initialize()->mutable_server()->set_id(1);
	if (!stream->Write(init)) {
		BOOST_LOG_TRIVIAL(error) << "write error";
		return 2;
	}

	while (true) {
		MurmurRPC::Authenticator_Response resp;
		MurmurRPC::Authenticator_Request req;
		if (!stream->Read(&req)) {
			BOOST_LOG_TRIVIAL(error) << "read error";
			return 2;
		}
		if (req.has_authenticate()) {
			if (!req.authenticate().has_name() || !req.authenticate().has_password()) {
				resp.mutable_authenticate()->set_status(MurmurRPC::Authenticator_Response_Status_Failure);
			} else {
				BOOST_LOG_TRIVIAL(info) << "starting authenticating " << req.authenticate().name();
				if (valid_user(req, resp)) {
					resp.mutable_authenticate()->set_status(MurmurRPC::Authenticator_Response_Status_Success);
					BOOST_LOG_TRIVIAL(info) << "successfully authenticated";
				} else {
					resp.mutable_authenticate()->set_status(MurmurRPC::Authenticator_Response_Status_Failure);
					BOOST_LOG_TRIVIAL(info) << "failure authenticating";
				}
			}
		} else if (req.has_find()) {
			struct passwd *info = nullptr;
			if (req.find().has_id()) {
				BOOST_LOG_TRIVIAL(info) << "starting find (id) " << req.find().id();
				info = getpwuid(req.find().id());
			} else if (req.find().has_name()) {
				BOOST_LOG_TRIVIAL(info) << "starting find (name) " << req.find().name();
				info = getpwnam(req.find().name().c_str());
			}
			resp.mutable_find();
			if (info) {
				BOOST_LOG_TRIVIAL(info) << "successfully found";
				auto user = resp.mutable_find()->mutable_user();
				user->set_id(info->pw_uid);
				user->set_name(info->pw_name);
			} else {
				BOOST_LOG_TRIVIAL(info) << "failure finding ";
			}
		}
		if (!stream->Write(resp)) {
			BOOST_LOG_TRIVIAL(error) << "write error";
			return 2;
		}
	}

	return 0;
}

int auth_callback(int num_msg, const struct pam_message *msg[], struct pam_response *resp[], void *appdata_ptr) {
	if (num_msg <= 0) {
		return PAM_CONV_ERR;
	}
	struct pam_response *r = (struct pam_response *)calloc(num_msg, sizeof(struct pam_response));
	int i;
	const MurmurRPC::Authenticator_Request *req = (MurmurRPC::Authenticator_Request *) appdata_ptr;
	for (i = 0; i < num_msg; i++) {
		switch (msg[i]->msg_style) {
		case PAM_PROMPT_ECHO_OFF:
			r[i].resp_retcode = 0;
			r[i].resp = strdup(req->authenticate().password().c_str());
			break;
		case PAM_PROMPT_ECHO_ON:
			r[i].resp_retcode = 0;
			r[i].resp = strdup(req->authenticate().name().c_str());
			break;
		}
	}
	*resp = r;
	return PAM_SUCCESS;
}

bool valid_user(const MurmurRPC::Authenticator_Request &req, MurmurRPC::Authenticator_Response &resp) {
	struct pam_conv pam_conversation;
	pam_conversation.conv = auth_callback;
	pam_conversation.appdata_ptr = (void *) &req;
	pam_handle_t *pamh;
	int ret = pam_start(SERVICE_NAME, NULL, &pam_conversation, &pamh);
	if (ret != PAM_SUCCESS) {
		return false;
	}
	ret = pam_authenticate(pamh, 0);
	if (ret != PAM_SUCCESS) {
		pam_end(pamh, ret);
		return false;
	}
	ret = pam_acct_mgmt(pamh, PAM_SILENT);
	if (ret != PAM_SUCCESS) {
		pam_end(pamh, ret);
		return false;
	}
	const void *item = 0;
	ret = pam_get_item(pamh, PAM_USER, &item);
	if (ret != PAM_SUCCESS) {
		pam_end(pamh, ret);
		return false;
	}
	char *username = (char *) item;
	struct passwd *info = getpwnam(username);
	if (info == NULL) {
		pam_end(pamh, ret);
		return false;
	}

	resp.mutable_authenticate()->set_id(info->pw_uid);
	resp.mutable_authenticate()->set_name(username);

	pam_end(pamh, ret);
	return true;
}
