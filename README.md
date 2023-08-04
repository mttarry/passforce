# PassForce
PassForce is a secure, command-line credentials management application for storing username/password combinations. Remember one master password to access account credentials for all the sites you visit. 

Account credentials are encrypted and only stored locally. Only by providing the correct master password will the database be decrypted so that modifications can be made. After each command, the database is re-encrypted using the master password. 

## Dependencies
PassForce uses libcrypto and libssl from OpenSSL. OpenSSL version 1.1.1 was used in the building of this project, but it should be compatible with later versions as well. 

## Usage
Build PassForce with `make` 
Enable debug print statements with `make debug` 

### Initializing the Database
PassForce requires a setup command to establish a master password and initialize the database. This MUST be run before any further interactions with the database. Maximum master password length is 128 characters. 

`./passforce -m MASTER_PASSWORD -i` 

### Adding Account Credentials
To add account credentials, the user provides the master password, as well as the entry information (site name, username, site password). 

`./passforce -m MASTER_PASSWORD -s SITE_NAME -n USERNAME -pSITE_PASSWORD` 

Note that SITE_PASSWORD must come immediately after the `-p` option. This is because a user may also opt to have PassForce generate a 128-character password for them, like so: 

`./passforce -m MASTER_PASSWORD -s SITE_NAME -n USERNAME -p -g` 

Attempting to add credentials for a SITE_NAME that has already been added to the database will result in a message that the credential has already been added. See [Updating Account Credentials](#updatingaccountcredentials) for info on how to update credentials. 


### Retrieving Account Credentials
To retrieve account credentials, the user provides the master password with the relevant SITE_NAME. 

`./passforce -m MASTER_PASSWORD -s SITE_NAME -r` 

### Deleting Account Credentials
To delete account credentials, the user provides the master password along with the relevant SITE_NAME. 

`./passforce -m MASTER_PASSWORD -s SITE_NAME -d` 

### Updating Account Credentials
Update account credentials is similar to adding credentials, except the user also provides the `-u` option. 

`./passforce -m MASTER_PASSWORD -s SITE_NAME -n USERNAME -pPASSWORD -u` 

Note that when updating passwords, the user may also specify the generate (`-g`) option to update the credentials with a 128-character randomly generated password. 

`./passforce -m MASTER_PASSWORD -s SITE_NAME -n USERNAME -p -g -u` 

### Retrieving All Account Credentials
The user may retrieve all account credentials by passing the `-a` option. This will print all site_name:username:password combinations. 

`./passforce -m MASTER_PASSWORD -a` 

## Design Notes
PassForce uses AES-256-CBC mode for encrypting the database. The master key, along with a random salt is used to derive a 256-bit AES key. The 144-byte PassForce header stores this salt as well as the initialization vector (IV) used to initialize the encryption context. The salt and IV can be publicly known, so there is no secure risk in storing these in the header. 

All content following the header contains the encrypted credentials. 