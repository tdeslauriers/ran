# ran


**Description:** Authentication service for machine to machine credentials.  Implements the client credentials grant flow of Oauth2 spec.  
* s2s jwt mint.
* source of truth for machine credentials and registry.
* source of truth for scopes simply because the table existed in this service first. 
* utilizes my [carapace](https://github.com/tdeslauriers/carapace) project for core microservice functionality.

**Name:** _Rán (燃) is the name of one of two twin dragons in_ Avatar: The Last Airbender.  _This service's authentication counterpart is the Shaw (shāo 燒) user service which handles human credentials_

* _Ran (燃) means "burn" or "ignite" in Chinese/Mandarin, and since all services need to get service credentials before taking any other action, the ignite side of the dragon pair seemed appropriate._  