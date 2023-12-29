# ran


**Description:** Authentication service for machine to machine credentials.  Implements the client credentials grant flow of Oauth2 spec.  
* source of truth for machine credentials and registry.
* s2s jwt mint.
* utilizes my [carapace](https://github.com/tdeslauriers/carapace) project for core microservice functionality.

**Name:** _Ran is the name of one of two twin dragons in Avatar.  This service's authentication counterpart will be Shaw (second dragon), which wil handle human credentials_
* _Ran (燃) means "burn" or "ignite" in Chinese, and since the gateway service erebor need to get service credentials to call Shaw with human credentials, the ignite side of the dragon pair seemed appropriate, since it must go first._  