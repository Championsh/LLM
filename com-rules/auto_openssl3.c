
    For any cryptographic function that generates a key or secret (such as DH_compute_key, compute_key, EVP_BytesToKey, etc.), use the following:

    Use sf_bitinit to mark the output buffer as initialized.
    Use sf_password_set to mark the output buffer as containing a password or secret.
    Use sf_buf_size_limit to set the buffer size limit based on the input parameters that specify the size of the output buffer and any other relevant parameters.
    If the function copies a buffer to the output buffer, use sf_bitcopy to mark the output buffer as copied from the input buffer.

    For any cryptographic function that uses a key or secret (such as EVP_CipherInit, EVP_DecryptInit, EVP_EncryptInit, etc.), use sf_password_use to mark the key or secret.
    For any function that sets a key or secret (such as CMS_RecipientInfo_set0_key, EVP_PKEY_CTX_set1_hkdf_key, EVP_PKEY_CTX_set_mac_key, etc.), use sf_password_use to mark the key or secret.
    For any function that gets a key or secret (such as EVP_PKEY_get_raw_private_key, get_priv_key, etc.), use sf_bitinit to mark the output buffer as initialized, sf_password_set to mark the output buffer as containing a password or secret, and sf_overwrite to mark any input/output parameters that specify the size of the output buffer.
    For any function that uses a password or passphrase (such as CTLOG_new_from_base64, PKCS5_PBKDF2_HMAC, PKCS5_PBKDF2_HMAC_SHA1, etc.), use sf_password_use to mark the password or passphrase.
    For any function that uses a salt value (such as EVP_BytesToKey, PKCS5_PBKDF2_HMAC, PKCS5_PBKDF2_HMAC_SHA1, etc.), use sf_password_use to mark the salt value.
    For any function that uses an initialization vector (IV) (such as EVP_CipherInit, EVP_DecryptInit, EVP_EncryptInit, etc.), use sf_password_use to mark the IV.
    For any function that generates a random number or uses a random value (such as EVP_CIPHER_CTX_rand_key, etc.), use sf_random_init to mark the output buffer as initialized and sf_random_use to mark any input parameters that are used to generate the random value.
    For any function that performs encryption or decryption (such as BF_cbc_encrypt, BF_cfb64_encrypt, BF_ofb64_encrypt, etc.), use sf_bitinit to mark the output buffer as initialized and sf_password_use to mark any input parameters that contain sensitive data (such as the input data, key, IV, etc.).
    For any function that performs a cryptographic hash or message authentication code (MAC) operation (such as EVP_PKEY_CTX_set1_hkdf_key, EVP_PKEY_CTX_set_mac_key, etc.), use sf_password_use to mark any input parameters that contain sensitive data (such as the key, message, etc.).
    For any function that performs a cryptographic signature or verification operation (such as EVP_PKEY_sign, EVP_PKEY_verify, etc.), use sf_password_use to mark any input parameters that contain sensitive data (such as the key, message, signature, etc.).
