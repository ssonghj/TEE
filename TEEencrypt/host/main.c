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

#include <err.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt_ta.h>

int main(int argc, char* argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t err_origin;
	char plaintext[64] = {0,};
	char ciphertext[64] = {0,};
	int len=64;

	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = plaintext;
	op.params[0].tmpref.size = len;
	
///////////////////////////////////////
	char *s1 = argv[1];
	char *s2 = "-e";
	int ret = strcmp(s1, s2);    // 두 문자열이 같은지 문자열 비교
	if(ret == 0){//같으면 암호화
		FILE *fp = fopen(argv[2], "r");//open file
		printf("========================Encryption========================\n");
		printf("Please Input Plaintext : ");	
		fread(plaintext,64,1,fp);//file read	
		printf("%s", plaintext);//print file
		fclose(fp);//close file
		
		memcpy(op.params[0].tmpref.buffer, plaintext, len);
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op,&err_origin);//enc
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
				res, err_origin);

		memcpy(ciphertext, op.params[0].tmpref.buffer, len+2);

		char split1[64] = {0,};//
		char split2 = '0';//enc_key store
		char *ptr = strtok(ciphertext, "\n");    //첫번째 strtok 사용.
		int cnt = 0;
		while (ptr != NULL)              //ptr이 NULL일때까지 (= strtok 함수가 NULL을 반환할때까지)
		{
			if(cnt==0){
				for(int i = 0; i<strlen(ptr); i++){
					split1[i]=ptr[i];
				}
				cnt++;
			}
			else {
				for(int i = 0; i<strlen(ptr); i++){
					split2=ptr[i];
				}
			}
	   		ptr = strtok(NULL, "\n");     //자른 문자 다음부터 구분자 또 찾기
		}
		printf("Ciphertext : %s\n", split1);

		FILE *fp2 = fopen("des.txt", "w+"); 
		fprintf(fp2, "%s_",split1);
		fprintf(fp2, "%c", split2);
		fputs("\n",fp2);
		fclose(fp2); //------------------------------------------>store ok

	}
	else{//다르면 복호화
		FILE *fp3 = fopen(argv[2], "r");//open file
		fread(ciphertext,64,1,fp3);//file read
		fclose(fp3);//close file

		printf("========================Decryption========================\n");
		printf("Please Input Ciphertext : ");
		char cipher[64]={0,};
		for(int i = 0; i<len; i++){
			if(ciphertext[i] == '_'){
				break;		
			}
			cipher[i] = ciphertext[i];
		}
		//printf("%s\n",cipher);
		printf("%s\n",cipher);
		memcpy(op.params[0].tmpref.buffer, ciphertext, len);
		
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op,&err_origin);//dec
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
				res, err_origin);
		memcpy(plaintext, op.params[0].tmpref.buffer, len);
		printf("Plaintext : %s\n", plaintext);
			
		FILE *fp4 = fopen("origin.txt", "w+"); 
		fprintf(fp4, "%s ",plaintext);
		fputs("\n",fp4);
		fclose(fp4); //------------------------------------------>store ok
		
	}
	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);

	return 0;
}
