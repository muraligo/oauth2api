# OAuth 2.0 Authorization Server

This provides the implementation of the 

## OAuth 2.0 Overview

In OAuth 2.0 we essentially have 4 roles as follows:
- Resource Server: provides an API to manage resources
- Resource Owner (a.k.a User): the user who has a subscription to types of resources managed within the Resource Server and therefore owns instances of those types of resources
- Client (3rd party app): that provides capabilities that the User would like to use but which needs access to resources owned by the user
- Authorization Server / Identity Provider (IdP): that manages identities of users and resources across parties

Noteworthy here is that the User and the Client need to separately **register** their identities with the IdP. The identity includes roles and permissions.

The authorization process occurs in a series of steps as follows:
1. Client Functionality Request: a user sends a request to the client API to access some of its functionality. The client recognizes it needs to access a resource on behalf of the user.
2. Authorization Request: the client sends a request to the IdP requesting access to a resource scope. The request includes a unique tag generated via a process established at the time of registration.
2a. The IdP pushes a **notification** to the user requesting confirmation for access to the resource scope by the client. This is sent via a mechanism pre-arranged during registration of the user.
2b. The user confirms the access request and responds as such to the IdP.
2c. This results in an **authorization code** which the IdP returns to the client along with the unique tag. The IdP response is actually a HTTP 302 redirect response with the redirect URL that the agent provides in the original request.
3. Token Request: The redirect to the new URL results in a request to the IdP with the **authorization code** for a token.
3a. After validating the **authorization code** the IdP responds with a **token** that has an **expiration** after which the client needs to repeat the authorization request. 
4. The client includes a redirect URL in the request which is then returned in a 302 response so the redirection results in a request with a token sent to the Resource Server.

In a variation on this where it is unsafe for the client to store its credentials for the IdP, the PKCE extension allows for the client to register a **code challenge** mechanism that it uses during its interactions with the IdP.

## Authorization Service Description

This service attempts to provide a simple Java implementation based in the HTTP functionality included in the JDK without using any features of JEE.

It uses an SPI for a data provider isolating it from any specific implementation.

This service offers 2 end points:
- code: provides the handling for the **Authorization Request** step above
- token: provides the handling for the **Token Request** step above


