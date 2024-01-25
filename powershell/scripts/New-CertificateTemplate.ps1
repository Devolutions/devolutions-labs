param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string] $BaseCertTypeName,
    [Parameter(Mandatory = $true, Position = 1)]
    [string] $NewCertTypeName,
    [Parameter(Mandatory = $true, Position = 2)]
    [string] $NewCertTypeFriendlyName,

    [switch] $EnrolleeSuppliesSubject,
    [switch] $AllowExportableKey,
    [switch] $EnableTemplate
)

$certca = @"
using System;
using System.Runtime.InteropServices;

public class CertCA
{
    public const uint CA_FLAG_ENUM_ALL_TYPES = 0x00000004;
    public const uint CT_FIND_LOCAL_SYSTEM = 0x00000002;
    public const uint CT_ENUM_MACHINE_TYPES = 0x00000040;
    public const uint CT_ENUM_USER_TYPES = 0x00000080;
    public const uint CT_FIND_BY_OID = 0x00000200;
    public const uint CT_FLAG_NO_CACHE_LOOKUP = 0x00000400;
    public const uint CT_FLAG_SCOPE_IS_LDAP_HANDLE = 0x00000800;
    public const uint CT_ENUM_ADMINISTRATOR_FORCE_MACHINE = 0x00001000;
    public const uint CT_ENUM_NO_CACHE_TO_REGISTRY = 0x00002000;
    public const uint CT_FLAG_ENUM_INCLUDE_INVALID_TYPES = 0x00004000;

    // Cert Type Flags
    public const uint CERTTYPE_ENROLLMENT_FLAG = 0x01;
    public const uint CERTTYPE_SUBJECT_NAME_FLAG = 0x02;
    public const uint CERTTYPE_PRIVATE_KEY_FLAG = 0x03;
    public const uint CERTTYPE_GENERAL_FLAG = 0x04;

    // Subject Name Flags
    public const uint CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001;
    public const uint CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME = 0x00010000;
    public const uint CT_FLAG_SUBJECT_REQUIRE_DIRECTORY_PATH = 0x80000000;
    public const uint CT_FLAG_SUBJECT_REQUIRE_COMMON_NAME = 0x40000000;
    public const uint CT_FLAG_SUBJECT_REQUIRE_EMAIL = 0x20000000;
    public const uint CT_FLAG_SUBJECT_REQUIRE_DNS_AS_CN = 0x10000000;
    public const uint CT_FLAG_SUBJECT_ALT_REQUIRE_DNS = 0x08000000;
    public const uint CT_FLAG_SUBJECT_ALT_REQUIRE_EMAIL = 0x04000000;
    public const uint CT_FLAG_SUBJECT_ALT_REQUIRE_UPN = 0x02000000;
    public const uint CT_FLAG_SUBJECT_ALT_REQUIRE_DIRECTORY_GUID = 0x01000000;
    public const uint CT_FLAG_SUBJECT_ALT_REQUIRE_SPN = 0x00800000;
    public const uint CT_FLAG_SUBJECT_ALT_REQUIRE_DOMAIN_DNS = 0x00400000;
    public const uint CT_FLAG_OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME = 0x00000008;

    // Private Key Flags
    public const uint CT_FLAG_ALLOW_PRIVATE_KEY_ARCHIVAL = 0x00000001;
    public const uint CT_FLAG_REQUIRE_PRIVATE_KEY_ARCHIVAL = CT_FLAG_ALLOW_PRIVATE_KEY_ARCHIVAL;
    public const uint CT_FLAG_EXPORTABLE_KEY = 0x00000010;
    public const uint CT_FLAG_STRONG_KEY_PROTECTION_REQUIRED = 0x00000020;

    [DllImport("certca.dll", CharSet = CharSet.Unicode)]
    public static extern int CAFindCertTypeByName(
        string wszCertType,
        IntPtr hCAInfo,
        uint dwFlags,
        out IntPtr phCertType
    );

    [DllImport("certca.dll", CharSet = CharSet.Unicode)]
    public static extern int CACloneCertType(
        IntPtr hCertType,
        string wszCertType,
        string wszFriendlyName,
        IntPtr pvldap,
        uint dwFlags,
        out IntPtr phCertType
    );

    [DllImport("certca.dll", CharSet = CharSet.Unicode)]
    public static extern int CASetCertTypeFlagsEx(
        IntPtr hCertType,
        uint dwOption,
        uint dwFlags
    );

    [DllImport("certca.dll", CharSet = CharSet.Unicode)]
    public static extern int CAUpdateCertType(
        IntPtr hCertType
    );

    [DllImport("certca.dll", CharSet = CharSet.Unicode)]
    public static extern int CACloseCertType(
        IntPtr hCertType
    );
}
"@

Add-Type -TypeDefinition $certca

$dwFlags = [CertCA]::CT_FLAG_NO_CACHE_LOOKUP -bor [CertCA]::CT_ENUM_MACHINE_TYPES -bor [CertCA]::CT_ENUM_USER_TYPES
$hCAInfo = [IntPtr]::Zero
$hBaseCertType = [IntPtr]::Zero
$hNewCertType = [IntPtr]::Zero

try {
    # Find base certificate template type
    $hr = [CertCA]::CAFindCertTypeByName($BaseCertTypeName, $hCAInfo, $dwFlags, [ref]$hBaseCertType)

    if ($hBaseCertType -eq [IntPtr]::Zero) {
        throw "Base certificate type '$BaseCertTypeName' not found."
    }

    # Clone base certificate template type
    $hr = [CertCA]::CACloneCertType($hBaseCertType, $NewCertTypeName, $NewCertTypeFriendlyName, [IntPtr]::Zero, 0, [ref]$hNewCertType)

    if ($hNewCertType -eq [IntPtr]::Zero) {
        if ($hr -eq 0x80092005) {
            throw "New certificate type '$NewCertTypeName' already exists."
        } else {
            throw "Failed to create new certificate type '$NewCertTypeName': 0x" + $hr.ToString("X")
        }
    }

    # Close base certificate template type handle
    $hr = [CertCA]::CACloseCertType($hBaseCertType)

    $subjectNameFlag = 0
    if ($EnrolleeSuppliesSubject) {
        # Subject Name: "supply in the request"
        $subjectNameFlag = [CertCA]::CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
    }
    $hr = [CertCA]::CASetCertTypeFlagsEx($hNewCertType, [CertCA]::CERTTYPE_SUBJECT_NAME_FLAG, $subjectNameFlag)

    $privateKeyFlag = 0
    if ($AllowExportableKey) {
        # Request Handling: "allow private key to be exported"
        $privateKeyFlag = [CertCA]::CT_FLAG_EXPORTABLE_KEY
    }
    $hr = [CertCA]::CASetCertTypeFlagsEx($hNewCertType, [CertCA]::CERTTYPE_PRIVATE_KEY_FLAG, $privateKeyFlag)

    # Save changes (write template to registry)
    $hr = [CertCA]::CAUpdateCertType($hNewCertType)

    # Close new certificate template type handle
    $hr = [CertCA]::CACloseCertType($hNewCertType)

    # Enable new certificate template type
    if ($EnableTemplate) {
        Add-CATemplate -Name $NewCertTypeName -Force
    }
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}

Write-Host "New certificate template '$NewCertTypeName' successfully created and configured."

# .\New-CertificateTemplate.ps1 "SmartcardLogon" "MySmartcardLogon" "My Smartcard Logon" -EnrolleeSuppliesSubject -AllowExportableKey -EnableTemplate
