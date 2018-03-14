/*-
 * Copyright (c) 2018 University Politehnica of Bucharest
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stdlib.h>
#include <socks6msg.h>

/*
 * helpers
 */

#define S6M_DIE_PTR(errcode) \
{\
	*err = (errcode); \
	return NULL; \
}

#define S6M_DIE_SSIZE(errcode) \
{\
	*err = errcode; \
	return -1; \
}

#define S6M_PACKED_SIZE(type)  S6M_ ## type ## _Packed_Size 

#define S6M_SIZE_CHECK(type, ptr) \
{ \
	int psize = S6M_PACKED_SIZE(type)((ptr), err); \
	if (psize < 0) \
		return -1; \
}

/*
 * S6M_Request_*
 */
ssize_t S6M_Request_Packed_Size(const struct S6M_Request *req, enum S6M_Error *err);
ssize_t S6M_Request_Pack(const struct S6M_Request *req, char *buf, int size, enum S6M_Error *err);
struct S6M_Request *S6M_Request_Parse(char *buf, int size, enum S6M_Error *err);

void S6M_Request_Free(struct S6M_Request *req)
{
	free(req->addr.domain);
	free(req->supportedMethods);
	free(req->userPasswdAuth.username);
	free(req->userPasswdAuth.passwd);
	free(req);
}

/*
 * S6M_AuthReply_*
 */

ssize_t S6M_AuthReply_Packed_Size(const struct S6M_AuthReply *authReply, enum S6M_Error *err);
ssize_t S6M_AuthReply_Pack(const struct S6M_AuthReply *authReply, char *buf, int size, enum S6M_Error *err);
struct S6M_AuthReply *S6M_AuthReply_Parse(char *buf, int size, enum S6M_Error *err);

void S6M_AuthReply_Free(struct S6M_AuthReply *authReply)
{
	free(authReply);
}

/*
 * S6M_OpReply_*
 */

ssize_t S6M_OpReply_Packed_Size(const struct S6M_OpReply *opReply, enum S6M_Error *err);
ssize_t S6M_OpReply_Pack(const struct S6M_OpReply *opReply, char *buf, int size, enum S6M_Error *err);
struct S6M_OpReply *S6M_OpReply_Parse(char *buf, int size, enum S6M_Error *err);

void S6M_OpReply_Free(struct S6M_OpReply *opReply)
{
	free(opReply->addr.domain);
	free(opReply);
}

/*
 * S6M_PasswdReq_*
 */

ssize_t S6M_PasswdReq_Packed_Size(const struct S6M_PasswdReq *pwReq, enum S6M_Error *err);
ssize_t S6M_PasswdReq_Pack(const struct S6M_PasswdReq *pwReq, char *buf, int size, enum S6M_Error *err);
struct S6M_PasswdReq *S6M_PasswdReq_Parse(char *buf, int size, enum S6M_Error *err);

void S6M_PasswdReq_Free(struct S6M_PasswdReq *pwReq)
{
	free(pwReq->username);
	free(pwReq->passwd);
	free(pwReq);
}

/*
 * S6M_PasswdReply_*
 */

ssize_t S6M_PasswdReply_Packed_Size(const struct S6M_PasswdReply *pwReply, enum S6M_Error *err)
{
	(void) pwReply; (void)err;
	return 2;
}

ssize_t S6M_PasswdReply_Pack(const struct S6M_PasswdReply *pwReply, char *buf, int size, enum S6M_Error *err)
{
	S6M_SIZE_CHECK(PasswdReply, pwReply);
	
	buf[0] = 0x01;
	buf[1] = pwReply->fail;
	return size;
}

struct S6M_PasswdReply *S6M_PasswdReply_Parse(char *buf, int size, enum S6M_Error *err)
{
	if (size < 2)
		S6M_DIE_PTR(S6M_ERROR_BUFFER);
	if (buf[0] != 0x01)
		S6M_DIE_PTR(S6M_ERROR_INVALID);
	
	int fail = buf[1];
	if (fail != 0 && fail != 1)
		S6M_DIE_PTR(S6M_ERROR_INVALID);
	
	struct S6M_PasswdReply *ret = malloc(2);
	if (!ret)
		S6M_DIE_PTR(S6M_ERROR_INVALID);
	
	ret->fail = fail;
	
	return ret;
}

void S6M_PasswdReply_Free(struct S6M_PasswdReply *pwReply)
{
	free(pwReply);
}
