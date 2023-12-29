# ran


**Description:** Authentication service for machine to machine credentials.  Implements the client credentials grant flow of Oauth2 spec.  
* source of truth for machine credentials and registry.
* s2s jwt mint.
* utilizes my [carapace](https://github.com/tdeslauriers/carapace) project for core microservice functionality.

**Name:** _Ran is the name of one of two twin dragons in Avatar.  This service's authentication counterpart will be the Shaw (second dragon) user service which will handle human credentials_
* _Ran (燃) means "burn" or "ignite" in Chinese, and since the gateway service, [erebor](https://github.com/tdeslauriers/erebor), needs to get service credentials before it can call any other services, the ignite side of the dragon pair seemed appropriate._  