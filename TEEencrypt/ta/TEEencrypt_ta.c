/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#define _CRT_SECURE_NO_WARNINGS    // strcat 보안 경고로 인한 컴파일 에러 방지
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <TEEencrypt_ta.h>

int key;
int root_key =3; /////////////////////////////////////////////////////////////미리 정의한 루트키
/*
 * Called when the instance of the TA is created. This is the first call in
 * the TA.
 */
TEE_Result TA_CreateEntryPoint(void)
{
	DMSG("has been called");

	return TEE_SUCCESS;
}

/*
 * Called when the instance of the TA is destroyed if the TA has not
 * crashed or panicked. This is the last call in the TA.
 */
void TA_DestroyEntryPoint(void)
{
	DMSG("has been called");
}

/*
 * Called when a new session is opened to the TA. *sess_ctx can be updated
 * with a value to be able to identify this session in subsequent calls to the
 * TA. In this function you will normally do the global initialization for the
 * TA.
 */
TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
		TEE_Param __maybe_unused params[4],
		void __maybe_unused **sess_ctx)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	DMSG("has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Unused parameters */
	(void)&params;
	(void)&sess_ctx;

	/*
	 * The DMSG() macro is non-standard, TEE Internal API doesn't
	 * specify any means to logging from a TA.
	 */
	IMSG("Caesar cipher ...\n");

	/* If return value != TEE_SUCCESS the session will not be created. */
	return TEE_SUCCESS;
}

/*
 * Called when a session is closed, sess_ctx hold the value that was
 * assigned by TA_OpenSessionEntryPoint().
 */
void TA_CloseSessionEntryPoint(void __maybe_unused *sess_ctx)
{
	(void)&sess_ctx; /* Unused parameter */
}
						//////////////////////////////////////////////enc value
static TEE_Result enc_value(uint32_t param_types,
	TEE_Param params[4])
{
	char * in = (char *)params[0].memref.buffer;
	int in_len = strlen (params[0].memref.buffer);
	char encrypted [64]={0,};

	DMSG("========================normal Encryption========================\n");
	DMSG ("Plaintext :  %s", in);
	memcpy(encrypted, in, in_len);

	for(int i=0; i<in_len;i++){
		if(encrypted[i]>='a' && encrypted[i] <='z'){
			encrypted[i] -= 'a';
			encrypted[i] += key;
			encrypted[i] = encrypted[i] % 26;
			encrypted[i] += 'a';
		}
		else if (encrypted[i] >= 'A' && encrypted[i] <= 'Z') {
			encrypted[i] -= 'A';
			encrypted[i] += key;
			encrypted[i] = encrypted[i] % 26;
			encrypted[i] += 'A';
		}
	}
	DMSG ("Ciphertext :  %s", encrypted);
	int enc_key = 0;	
	enc_key = (key+root_key)%26;
	encrypted[in_len] = 32;				//space
	encrypted[in_len+1] = enc_key+65;		//'A'+enc_key
	in_len += 2;
	memcpy(in, encrypted, in_len);		//copy
	return TEE_SUCCESS;
}
							////////////////////////////////////////////dec
static TEE_Result dec_value(uint32_t param_types,
	TEE_Param params[4])
{
	char * in = (char *)params[0].memref.buffer;
	int in_len = strlen (params[0].memref.buffer);
	char decrypted [64]={0,};
	memcpy(decrypted, in, in_len);
	
	///////////////////////////////////////////2) TA에서 암호화된 키를 root키로 복호화
	DMSG("========================key Decryption========================\n");
		for(int i = 0; i< in_len; i++){
		if(decrypted[i] == '_'){
			key = ((int)decrypted[i+1])-65-root_key;//original_key 
		}
	}
	///////////////////////////////////////////////3) 랜덤키로 암호문을 복호화
	DMSG("========================Decryption========================\n");
	DMSG ("Ciphertext :  %s", in);
	memcpy(decrypted, in, in_len);

	for(int i=0; i<in_len;i++){
		if(decrypted[i]>='a' && decrypted[i] <='z'){
			decrypted[i] -= 'a';
			decrypted[i] -= key;
			decrypted[i] += 26;
			decrypted[i] = decrypted[i] % 26;
			decrypted[i] += 'a';
		}
		else if (decrypted[i] >= 'A' && decrypted[i] <= 'Z') {
			decrypted[i] -= 'A';
			decrypted[i] -= key;
			decrypted[i] += 26;
			decrypted[i] = decrypted[i] % 26;
			decrypted[i] += 'A';
		}
	}
	char dec[64]={0,};
	for(int i = 0; i<in_len; i++){
		if(decrypted[i] == '_'){
			break;		
		}
		dec[i] = decrypted[i];
	}
	DMSG ("Plaintext :  %s", dec);
	memcpy(in, dec, in_len);

	return TEE_SUCCESS;
}


/*
 * Called when a TA is invoked. sess_ctx hold that value that was
 * assigned by TA_OpenSessionEntryPoint(). The rest of the paramters
 * comes from normal world.
 */
TEE_Result TA_InvokeCommandEntryPoint(void __maybe_unused *sess_ctx,uint32_t cmd_id,
			uint32_t param_types, TEE_Param params[4])
{
	(void)&sess_ctx; /* Unused parameter */
	
	char chHex[10];
	while(key == 0){
	TEE_GenerateRandom(chHex, sizeof(chHex));
	printf("chHex : (%x)\n",chHex);
    	unsigned int nResult = 0;    
   	for ( int i = 0; i <= strlen(chHex); i++ )// 16 -> 10 
  	{
		if ( chHex[i] >= 'A' && chHex[i] <= 'F' )   // chHex값이 'A'(65)~'F'(70) 일때
	    	nResult = nResult * 16 + chHex[i] - 'A' + 10;
       		else if ( chHex[i] >= 'a' && chHex[i] <= 'f' )      // chHex값이 'a'(97)~'f'(102) 일때
	    	nResult = nResult * 16 + chHex[i] - 'a' + 10;
		else if ( chHex[i] >= '0' && chHex[i] <= '9' )      // chHex값이 '0'(48)~'9'(57) 일때
	    	nResult = nResult * 16 + chHex[i] - '0';
  	}
	key = nResult % 26;
	}
	printf("key : %d\n",key);

	switch (cmd_id) {
	case TA_TEEencrypt_CMD_ENC_VALUE://랜덤키로 평문 암호화, 랜덤키는 TA의 root키로 암호화
		return enc_value(param_types, params);
	case TA_TEEencrypt_CMD_DEC_VALUE: 
		return dec_value(param_types, params);

	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
	int close(int fd); 
}
