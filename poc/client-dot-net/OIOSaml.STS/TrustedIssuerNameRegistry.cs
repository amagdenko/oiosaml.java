﻿//-----------------------------------------------------------------------------
//
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (c) Microsoft Corporation. All rights reserved.
//
//
//-----------------------------------------------------------------------------


using System;
using System.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens;

/// <summary>
/// IssuerNameRegistry that validates the incoming SAML token issuer.
/// </summary>
public class TrustedIssuerNameRegistry : IssuerNameRegistry
{
    /// <summary>
    /// Overrides the base class. Validates the given issuer token. For a incoming SAML token
    /// the issuer token is the Certificate that signed the SAML token.
    /// </summary>
    /// <param name="securityToken">Issuer token to be validated.</param>
    /// <returns>Friendly name representing the Issuer.</returns>
    public override string GetIssuerName(SecurityToken securityToken)
    {
        X509SecurityToken x509Token = securityToken as X509SecurityToken;
        if (x509Token != null)
        {
            return x509Token.Certificate.SubjectName.Name;
        }

        throw new SecurityTokenException("Untrusted issuer.");
    }
}
