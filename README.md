<p align="center">
  <a href="https://logto.io" target="_blank" align="center" alt="Logto Logo">
      <img src="./logo.png" width="100">
  </a>
  <br/>
  <span><i><a href="https://logto.io" target="_blank">Logto</a> helps you build the sign-in experience and user identity within minutes.</i></span>
</p>

# Logto Rust *Unofficial* SDKs - WORK IN PROGRESS
The repo for SDKs and working samples written in Rust.

Currently there is no integration tutorial, as the project is still a work in progress

## Installation

TBD

## Packages

| Name   | Description                                     |
| ------ | ------------------------------------            |
| core   | Logto SDK core package                          |
| utils  | Helper functions specified at Logto's SDK specs |

## Resources

[![Website](https://img.shields.io/badge/website-logto.io-8262F8.svg)](https://logto.io/)
[![Docs](https://img.shields.io/badge/docs-logto.io-green.svg)](https://docs.logto.io/)
[![Discord](https://img.shields.io/discord/965845662535147551?logo=discord&logoColor=ffffff&color=7389D8&cacheSeconds=600)](https://discord.gg/UEPaF3j5e6)

## Disclaimers
- This repo is not an official Logto repo, but it would be nice to be so one day.
- I based my implementation going back-and-forth with Logto's SDKs in Kotlin, JS and Go. You will see that the code has a lot of similarities taken from those 3 codebases.
- **Help is needed and appreciated! This is my first Rust library, so I will be glad to have any feedback and help in organising the code better.**
- The project is not feature complete. Here is an advanced feature tracking system, also called todo list:

## SDK Convention
### Core
#### Core functions
  - [x] fetchOidcConfig
  - [x] generateSignInUri
  - [x] generateSignOutUri
  - [x] fetchTokenByAuthorizationCode
  - [x] fetchTokenByRefreshToken
  - [x] revoke
#### Utility functions
  - [x] generateCodeVerifier
  - [x] generateCodeChallenge
  - [x] generateState
  - [x] decodeIdToken
  - [x] verifyIdToken
  - [x] verifyAndParseCodeFromCallbackUri
#### Types
  - [x] OidcConfigResponse
  - [x] CodeTokenResponse
  - [x] RefreshTokenResponse
  - [x] IdTokenClaims
### Platform SDK
#### Basic types
  - [ ] LogtoConfig
  - [ ] AccessToken
#### LogtoClient
##### Properties
  - [ ] logtoConfig
  - [ ] oidcConfig
  - [ ] accessTokenMap
  - [ ] refreshToken
  - [ ] idToken
##### Methods
  - [ ] constructor
  - [ ] isAuthenticated
  - [ ] SignIn
  - [ ] SignOut
  - [ ] getAccessToken
  - [ ] getIdTokenClaims
