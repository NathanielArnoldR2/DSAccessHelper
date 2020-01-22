function Get-DSSchemaGuid {
  [CmdletBinding()]
  param(
    [Parameter(
      Mandatory = $true
    )]
    [string]
    $ContainerName
  )
  Get-ADObject "CN=$($ContainerName),$((Get-ADRootDSE).schemaNamingContext)" -Properties schemaIDGUID |
    ForEach-Object {[guid]$_.schemaIDGUID}
}

function Get-DSRightsGuid {
  [CmdletBinding()]
  param(
    [Parameter(
      Mandatory = $true
    )]
    [string]
    $ContainerName
  )
  Get-ADObject "CN=$($ContainerName),CN=Extended-Rights,$((Get-ADRootDSE).configurationNamingContext)" -Properties rightsGuid |
    ForEach-Object {[guid]$_.rightsGuid}
}

function Get-ExtendedRightsGuidResolutionCache {
  Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).configurationNamingContext)" -SearchScope OneLevel -Filter * -Properties rightsGUID,validAccesses |
    ForEach-Object {
      [PSCustomObject]@{
        Name = $_.Name
        DistinguishedName = $_.DistinguishedName
        ObjectClass = $_.ObjectClass
        ObjectGUID = $_.ObjectGUID
        rightsGUID = $_.rightsGUID
        validAccesses = [System.DirectoryServices.ActiveDirectoryRights]$_.validAccesses
      }
    }
}

function Get-SchemaIdGuidResolutionCache {
  Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext -SearchScope OneLevel -Filter * -Properties attributeSecurityGUID,schemaIDGUID |
    ForEach-Object {
      [PSCustomObject]@{
        Name = $_.Name
        DistinguishedName = $_.DistinguishedName
        ObjectClass = $_.ObjectClass
        ObjectGUID = if ($null -ne $_.ObjectGUID) {[guid]$_.ObjectGUID};
        attributeSecurityGUID = if ($null -ne $_.attributeSecurityGUID) {[guid]$_.attributeSecurityGUID};
        schemaIDGUID = if ($null -ne $_.schemaIDGUID) {[guid]$_.schemaIDGUID};
      }
    }
}

function Get-DSPropertySetMembers {
  [CmdletBinding()]
  param(
    [Parameter(
      Mandatory = $true
    )]
    [string]
    $ContainerName
  )

  $rightsGuid = Get-DSRightsGuid $ContainerName

  Get-SchemaIdGuidResolutionCache |
    Where-Object attributeSecurityGUID -eq $rightsGuid |
    ForEach-Object Name
}

function Get-DSAclRule {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true,
      ValueFromPipeline = $true
    )]
    [Microsoft.ActiveDirectory.Management.ADObject]
    $InputObject,

    [switch]
    $Audit,

    [switch]
    $IncludeInherited,

    [switch]
    $IncludeDefaultAccessRules,

    [switch]
    $IncludeProtectedFromAccidentalDeletion
  )

  $params = @{
    Path = (Join-Path -Path AD:\ -ChildPath $InputObject.DistinguishedName)
  }

  if ($Audit) {
    $params.Audit = $true
  }

  $acl = Get-Acl @params

  if ($Audit) {
    $rules = $acl.Audit
  } else {
    $rules = $acl.Access
  }

  if (-not $IncludeInherited) {
    $rules = @(
      $rules |
        Where-Object IsInherited -eq $false
    )
  }

  if (-not $Audit) {
    if (-not $IncludeDefaultAccessRules) {
      $objectCategory = (Get-ADObject $InputObject.DistinguishedName -Properties ObjectCategory).ObjectCategory
      
      $sddl = (Get-ADObject $objectCategory -Properties defaultSecurityDescriptor).defaultSecurityDescriptor

      if ($null -ne $sddl) {
        $defAcl = [System.DirectoryServices.ActiveDirectorySecurity]::new()
        $defAcl.SetSecurityDescriptorSddlForm($sddl)

        $defAcl.Access |
          ForEach-Object {
            $defRule = $_

            $rules = @(
              $rules |
                Where-Object {
                  -not (
                    $_.ActiveDirectoryRights -eq $defRule.ActiveDirectoryRights -and
                    $_.InheritanceType -eq $defRule.InheritanceType -and
                    $_.ObjectType -eq $defRule.ObjectType -and
                    $_.InheritedObjectType -eq $defRule.InheritedObjectType -and
                    $_.ObjectFlags -eq $defRule.ObjectFlags -and
                    $_.AccessControlType -eq $defRule.AccessControlType -and
                    $_.IdentityReference -eq $defRule.IdentityReference -and
                    $_.IsInherited -eq $defRule.IsInherited -and
                    $_.InheritanceFlags -eq $defRule.InheritanceFlags -and
                    $_.PropagationFlags -eq $defRule.PropagationFlags
                  )
                }
            )
          }
      }
    }

    if (-not $IncludeProtectedFromAccidentalDeletion) {
      $rules = @(
        $rules |
          Where-Object {
            -not (
              $_.ActiveDirectoryRights -eq (
                [System.DirectoryServices.ActiveDirectoryRights]::DeleteChild -bor
                [System.DirectoryServices.ActiveDirectoryRights]::DeleteTree -bor
                [System.DirectoryServices.ActiveDirectoryRights]::Delete
              ) -and
              $_.InheritanceType -eq [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None -and
              $_.ObjectType -eq [guid]::Empty -and
              $_.InheritedObjectType -eq [guid]::Empty -and
              $_.ObjectFlags -eq [System.Security.AccessControl.ObjectAceFlags]::None -and
              $_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Deny -and
              $_.IdentityReference -eq [System.Security.Principal.NTAccount]"Everyone" -and
              $_.IsInherited -eq $false -and
              $_.InheritanceFlags -eq [System.Security.AccessControl.InheritanceFlags]::None -and
              $_.PropagationFlags -eq [System.Security.AccessControl.PropagationFlags]::None
            )
          }
      )
    }
  }

  $rules
}

function Format-DSAclRule {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true,
      ValueFromPipeline = $true
    )]
    [System.Security.AccessControl.AuthorizationRule]
    $InputObject
  )
  begin {
    $rightsGuidCache = Get-ExtendedRightsGuidResolutionCache
    $schemaGuidCache = Get-SchemaIdGuidResolutionCache

function Resolve-ObjectType {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Position = 0,
      Mandatory = $true
    )]
    [guid]
    $ObjectType,

    [Parameter(
      Mandatory = $true
    )]
    [ValidateSet("ObjectType", "InheritedObjectType")]
    [string]
    $Context
  )

  if ($ObjectType -eq [guid]::Empty) {
    return "[all]"
  }

  $output = @()

  $rights = @(
    $rightsGuidCache |
      Where-Object rightsGUID -eq $ObjectType |
      Where-Object {($InputObject.ActiveDirectoryRights -band $_.validAccesses) -gt 0}
  )

  $rights |
    ForEach-Object {
      if ($_.validAccesses -eq [System.DirectoryServices.ActiveDirectoryRights]::Self) {
        $output += "Validated Write: $($_.Name)"
      } elseif ($_.validAccesses -eq ([System.DirectoryServices.ActiveDirectoryRights]::ReadProperty -bor [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty)) {
        $output += "Property Set: $($_.Name)"
      } elseif ($_.validAccesses -eq [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) {
        $output += "Extended Right: $($_.Name)"
      }
    }

  if (-not ($Context -eq "ObjectType" -and $InputObject.ActiveDirectoryRights -eq [System.DirectoryServices.ActiveDirectoryRights]::Self)) {
    $schemaItems = @(
      $schemaGuidCache |
        Where-Object schemaIDGUID -eq $ObjectType
    )
    
    $schemaItems |
      ForEach-Object {
        if ($_.ObjectClass -eq "classSchema") {
          $output += "Object: $($_.Name)"
        } elseif ($_.ObjectClass -eq "attributeSchema") {
          $output += "Property: $($_.Name)"
        }
      }
  }

  if ($output.Count -eq 0) {
    return "[unknown]"
  } else {
    return $output -join " -OR- "
  }
}

  }

  process {
    $outHash = [ordered]@{
      IdentityReference = $InputObject.IdentityReference
    }

    if ($InputObject -is [System.DirectoryServices.ActiveDirectoryAccessRule]) {
      $outHash.AccessControlType = $InputObject.AccessControlType
    } elseif ($InputObject -is [System.DirectoryServices.ActiveDirectoryAuditRule]) {
      $outHash.AuditFlags = $InputObject.AuditFlags
    }

    $outHash.ActiveDirectoryRights = $InputObject.ActiveDirectoryRights

    $outHash.ObjectType = Resolve-ObjectType $InputObject.ObjectType -Context ObjectType

    $outHash.InheritanceType = $InputObject.InheritanceType

    if (
      $InputObject.InheritanceType -ne [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None -or
      $InputObject.InheritedObjectType -ne [guid]::Empty
    ) {
      $outHash.InheritedObjectType = Resolve-ObjectType $InputObject.InheritedObjectType -Context InheritedObjectType
    }

    [PSCustomObject]$outHash
  }
}

function Add-DSOUAccess {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      ValueFromPipeline = $true,
      Mandatory = $true
    )]
    [Microsoft.ActiveDirectory.Management.ADOrganizationalUnit]
    $OrganizationalUnit,

    [Parameter(
      Mandatory = $true
    )]
    [Microsoft.ActiveDirectory.Management.ADPrincipal[]]
    $Principal,

    [Parameter(
      Mandatory = $true
    )]
    [string]
    $AccessProfile,

    [ValidateSet("Manageability", "LeastPrivilege")]
    [string]
    $Target = "Manageability"
  )
  begin{

$accessProfiles = @{}

$accessProfiles.ComputerManage = {

# Used for pre-stage, join, and move-to operations.
$acl.AddAccessRule([System.DirectoryServices.ActiveDirectoryAccessRule]::new(
  $thisPrincipal.SID,
  [System.DirectoryServices.ActiveDirectoryRights]::CreateChild,
  [System.Security.AccessControl.AccessControlType]::Allow,
  (Get-DSSchemaGuid Computer),
  [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All,
  (Get-DSSchemaGuid Organizational-Unit)
))

# Delete is used for move-from operations, as well as deletion. DeleteTree
# permits recursive deletion of nested objects while deleting the computer,
# and (provided the caller exercises the API function, rather than trying
# to delete children before deleting the object itself) obviates direct
# permission assignment to delete these children.
#
# These direct permissions are specified in the ACL to support use of both
# Delete (default removal via ADUC) and DeleteTree (Remove-ADObject with
# the Recursive switch). Permission is specific to "Service-Connection-
# Point" for least privilege, as it is an object of this type generated
# by Hyper-V VM systems that has complicated deletion in my labs.
if ($Target -eq "Manageability") {

  # For manageability, Delete, DeleteTree, and DeleteChild (not filtered by
  # object class) are combined. Resulting ACL entry will show as Access
  # "Special" in the Advanced Permissions GUI, but at least there will be
  # only one entry with that designation.

  $acl.AddAccessRule([System.DirectoryServices.ActiveDirectoryAccessRule]::new(
    $thisPrincipal.SID,
    [System.DirectoryServices.ActiveDirectoryRights]::Delete -bor
    [System.DirectoryServices.ActiveDirectoryRights]::DeleteTree -bor
    [System.DirectoryServices.ActiveDirectoryRights]::DeleteChild,
    [System.Security.AccessControl.AccessControlType]::Allow,
    [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,
    (Get-DSSchemaGuid Computer)
  ))

}  elseif ($Target -eq "LeastPrivilege") {

  $acl.AddAccessRule([System.DirectoryServices.ActiveDirectoryAccessRule]::new(
    $thisPrincipal.SID,
    [System.DirectoryServices.ActiveDirectoryRights]::Delete -bor
    [System.DirectoryServices.ActiveDirectoryRights]::DeleteTree,
    [System.Security.AccessControl.AccessControlType]::Allow,
    [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,
    (Get-DSSchemaGuid Computer)
  ))

  $acl.AddAccessRule([System.DirectoryServices.ActiveDirectoryAccessRule]::new(
    $thisPrincipal.SID,
    [System.DirectoryServices.ActiveDirectoryRights]::DeleteChild,
    [System.Security.AccessControl.AccessControlType]::Allow,
    (Get-DSSchemaGuid Service-Connection-Point),
    [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,
    (Get-DSSchemaGuid Computer)
  ))

}

# Validated SPN/DNS and Reset Password are the three basic rights needed for
# most join/unjoin operations.
$acl.AddAccessRule([System.DirectoryServices.ActiveDirectoryAccessRule]::new(
  $thisPrincipal.SID,
  [System.DirectoryServices.ActiveDirectoryRights]::Self, # Required for validated writes.
  [System.Security.AccessControl.AccessControlType]::Allow,
  (Get-DSRightsGuid Validated-SPN),
  [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,
  (Get-DSSchemaGuid Computer)
))
$acl.AddAccessRule([System.DirectoryServices.ActiveDirectoryAccessRule]::new(
  $thisPrincipal.SID,
  [System.DirectoryServices.ActiveDirectoryRights]::Self, # Required for validated writes.
  [System.Security.AccessControl.AccessControlType]::Allow,
  (Get-DSRightsGuid Validated-DNS-Host-Name),
  [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,
  (Get-DSSchemaGuid Computer)
))
$acl.AddAccessRule([System.DirectoryServices.ActiveDirectoryAccessRule]::new(
  $thisPrincipal.SID,
  [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
  [System.Security.AccessControl.AccessControlType]::Allow,
  (Get-DSRightsGuid User-Force-Change-Password),
  [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,
  (Get-DSSchemaGuid Computer)
))

# "User-Account-Restrictions" is a property set that encompasses ~3 properties
# in addition to the four enumerated below for least privilege. "User-Account-
# Control" is required for all domain-join operations; the other three are
# required for disjoin.
if ($Target -eq "Manageability") {
  $acl.AddAccessRule([System.DirectoryServices.ActiveDirectoryAccessRule]::new(
    $thisPrincipal.SID,
    [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
    [System.Security.AccessControl.AccessControlType]::Allow,
    (Get-DSRightsGuid User-Account-Restrictions),
    [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,
    (Get-DSSchemaGuid Computer)
  ))
} elseif ($Target -eq "LeastPrivilege") {
  "Account-Expires",
  "Pwd-Last-Set",
  "User-Account-Control",
  "User-Parameters" |
    ForEach-Object {
      $acl.AddAccessRule([System.DirectoryServices.ActiveDirectoryAccessRule]::new(
        $thisPrincipal.SID,
        [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
        [System.Security.AccessControl.AccessControlType]::Allow,
        (Get-DSSchemaGuid $_),
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,
        (Get-DSSchemaGuid Computer)
      ))
    }
}

# "Public-Information" is a property set that encompasses 42 (!) properties in
# addition to the two enumerated below for least privilege. Both properties are
# needed for move operations.
if ($Target -eq "Manageability") {
  $acl.AddAccessRule([System.DirectoryServices.ActiveDirectoryAccessRule]::new(
    $thisPrincipal.SID,
    [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
    [System.Security.AccessControl.AccessControlType]::Allow,
    (Get-DSRightsGuid Public-Information),
    [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,
    (Get-DSSchemaGuid Computer)
  ))
} elseif ($Target -eq "LeastPrivilege") {
  "Common-Name",
  "RDN" |
    ForEach-Object {
      $acl.AddAccessRule([System.DirectoryServices.ActiveDirectoryAccessRule]::new(
        $thisPrincipal.SID,
        [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
        [System.Security.AccessControl.AccessControlType]::Allow,
        (Get-DSSchemaGuid $_),
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,
        (Get-DSSchemaGuid Computer)
      ))
    }
}

}
$accessProfiles.WriteGroupMember = {

$acl.AddAccessRule([System.DirectoryServices.ActiveDirectoryAccessRule]::new(
  $thisPrincipal.SID,
  [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
  [System.Security.AccessControl.AccessControlType]::Allow,
  (Get-DSSchemaGuid Member),
  [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,
  (Get-DSSchemaGuid Group)
))

}
$accessProfiles.UserPasswordTriage = {

$acl.AddAccessRule([System.DirectoryServices.ActiveDirectoryAccessRule]::new(
  $thisPrincipal.SID,
  [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
  [System.Security.AccessControl.AccessControlType]::Allow,
  (Get-DSRightsGuid User-Force-Change-Password),
  [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,
  (Get-DSSchemaGuid User)
))

$acl.AddAccessRule([System.DirectoryServices.ActiveDirectoryAccessRule]::new(
  $thisPrincipal.SID,
  [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
  [System.Security.AccessControl.AccessControlType]::Allow,
  (Get-DSSchemaGuid Pwd-Last-Set),
  [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,
  (Get-DSSchemaGuid User)
))

$acl.AddAccessRule([System.DirectoryServices.ActiveDirectoryAccessRule]::new(
  $thisPrincipal.SID,
  [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
  [System.Security.AccessControl.AccessControlType]::Allow,
  (Get-DSSchemaGuid Lockout-Time),
  [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,
  (Get-DSSchemaGuid User)
))

}

  } process {
    try {
      $OUPSPath = Join-Path -Path AD:\ -ChildPath $OrganizationalUnit.DistinguishedName

      $Acl = Get-Acl -Path $OUPSPath

      foreach ($ThisPrincipal in $Principal) {
        & $accessProfiles.$AccessProfile
      }

      $Acl |
        Set-Acl
    } catch {
      $PSCmdlet.ThrowTerminatingError($_)
    }
  }
}

function Enable-DSAccessAudit {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [switch]
    $KeepExistingEvents
  )
  try {

    & auditpol /set /category:* /success:disable /failure:disable |
      Out-Null

    & auditpol /set /category:"Account Management" /success:enable /failure:enable |
      Out-Null

    & auditpol /set /category:"DS Access" /success:enable /failure:enable |
      Out-Null

    $adRootDse = Get-ADRootDSE

    "defaultNamingContext",
    "configurationNamingContext",
    "schemaNamingContext" |
      ForEach-Object {
        $dn = $adRootDse.$_

        $acl = Get-Acl -Path (Join-Path -Path AD:\ -ChildPath $dn) -Audit

        $acl.AddAuditRule([System.DirectoryServices.ActiveDirectoryAuditRule]::new(
          [System.Security.Principal.NTAccount]"Everyone",
          [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
          [System.Security.AccessControl.AuditFlags]::Success -bor
          [System.Security.AccessControl.AuditFlags]::Failure,
          [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All
        ))

        $acl |
          Set-Acl
      }

    if (-not $KeepExistingEvents) {
      Clear-EventLog -LogName Security
    }
  } catch {
    $PSCmdlet.ThrowTerminatingError($_)
  }
}

function Disable-DSAccessAudit {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param()
  try {
    & auditpol /set /category:* /success:disable /failure:disable |
      Out-Null
  } catch {
    $PSCmdlet.ThrowTerminatingError($_)
  }
}

function Get-DSAccessEvent {
  [CmdletBinding()]
  param()

  Get-WinEvent -LogName Security -FilterXPath "Event[System/EventID = 4662]"
}

function Export-DSAccessEvent {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true
    )]
    [String]
    $Path,

    [ValidateSet(
      "Ignore",
      "Throw",
      "Notify"
    )]
    [string]
    $OnEmpty = "Ignore"
  )

  # Xml is constructed to export all security logs excepting the log clearance
  # and audit policy change notifications. Whether these would otherwise be
  # present is down to vagaries of timing.
  $Xml = [xml]@"
<QueryList>
  <Query Id="0">
    <Select Path="Security">Event</Select>
    <Suppress Path="Security">Event[System/Provider/@Name = 'Microsoft-Windows-Eventlog' and System/EventID = 1102]</Suppress>
    <Suppress Path="Security">Event[System/Provider/@Name = 'Microsoft-Windows-Security-Auditing' and System/EventID = 4719]</Suppress>
  </Query>
</QueryList>
"@

  $xmlPath = New-Item -Path $env:TEMP `
                      -Name "$([System.Guid]::NewGuid()).xml" |
               ForEach-Object FullName

  # If we don't specify encoding, wevtutil will choke on the (default)
  # ANSI-encoded output.
  Set-Content -LiteralPath $xmlPath -Value $Xml.OuterXml -Encoding Unicode

  & wevtutil export-log $xmlPath $Path /structuredquery:true |
    Out-Null

  Remove-Item -LiteralPath $xmlPath

  if ($OnEmpty -eq "Ignore") {
    return
  }

  # The PowerShell-native equivalent of getting the record count of an
  # event log export requires special handling of an error when the
  # export contains 0 events.
  #
  # It *also* locks(!) the log file, preventing the later removal we
  # require.
  $eventCount = & wevtutil get-loginfo $Path /logfile:true |
                  Where-Object {$_ -match "^numberOfLogRecords: "} |
                  ForEach-Object {[int](($_ -replace "^numberOfLogRecords: ","").Trim())}

  if ($eventCount -gt 0) {
    return
  }

  if ($OnEmpty -eq "Throw") {
    throw "wevtutil log export returned no events."
  } elseif ($OnEmpty -eq "Notify") {
    $evtxItem = Get-Item -LiteralPath $Path

    New-Item -Path $evtxItem.DirectoryName -Name "$($evtxItem.BaseName).empty.log" -ItemType File |
      Out-Null

    Remove-Item -LiteralPath $evtxItem.FullName
  }
}

function Format-DSAccessEvent {
  [CmdletBinding(
    PositionalBinding = $false
  )]
  param(
    [Parameter(
      Mandatory = $true,
      ValueFromPipeline = $true
    )]
    [System.Diagnostics.Eventing.Reader.EventLogRecord]
    $InputObject
  )
  begin {
    $elevated = [System.Security.Principal.WindowsPrincipal]::new(
      [System.Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-not $elevated) {
      Write-Warning "Results may not be accurate w/r/t 'AccessedObject'; Deleted Objects access requires the cmdlet be run in an elevated process."
    }

    $rightsGuidCache = Get-ExtendedRightsGuidResolutionCache
    $schemaGuidCache = Get-SchemaIdGuidResolutionCache

    $domainInfo = Get-ADDomain

    $dnsRootRegex = "^$([regex]::Escape($domainInfo.DNSRoot))"
  }
  process {
    try {
      $accessedObject = Get-ADObject -Identity $InputObject.Properties[6].Value.Substring(1) -Properties CanonicalName -IncludeDeletedObjects -ErrorAction Stop
    } catch {
      $Global:Error.RemoveAt(0)

      $accessedObject = $null
    }

    $startPattern = "^(?:(?:---)|(?:$($InputObject.Properties[9].Value.Trim())))"
    $eventGuids = @(
      ($InputObject.Properties[11].Value -replace $startPattern,"").Trim() -split "`n" |
        ForEach-Object {
          $guid = [guid]::Empty

          if ([guid]::TryParse($_, [ref]$guid)) {
            $guid
          }
        } |
        Sort-Object -Unique
    )

    $schemaMatches = @()
    $rightsMatches = @()

    $eventGuids |
      ForEach-Object {
        $schemaMatches += @(
          $schemaGuidCache |
            Where-Object schemaIDGUID -eq $_
        )

        $rightsMatches += @(
          $rightsGuidCache |
            Where-Object rightsGUID -eq $_
        )
      }

    $objectMatches = @(
      $schemaMatches |
        Where-Object ObjectClass -eq classSchema |
        Group-Object DistinguishedName |
        Sort-Object Count -Descending |
        ForEach-Object {
          $_.Group[0].Name
        }
    )

    $propertySetMatches = @(
      $rightsMatches |
        Group-Object DistinguishedName |
        Sort-Object Count -Descending |
        ForEach-Object {
          $_.Group[0].Name
        }
    )

    $propertyMatches = @(
      $schemaMatches |
        Where-Object ObjectClass -eq attributeSchema |
        Group-Object DistinguishedName |
        Sort-Object Count -Descending |
        ForEach-Object {
          $_.Group[0].Name
        }
    )

    [PSCustomObject]@{
      "TimeCreated"                = $InputObject.TimeCreated
      "AccessorAccount"            = "$($InputObject.Properties[2].Value)\$($InputObject.Properties[1].Value)"
      "AccessedObject.Name"        = if ($null -ne $accessedObject) {$accessedObject.Name};
      "AccessedObject.Path"        = if ($null -ne $accessedObject) {"/" + ($accessedObject.CanonicalName -replace $dnsRootRegex,$domainInfo.NetBIOSName -replace "/$","")};
      "AccessedObject.Class"       = if ($null -ne $accessedObject) {$accessedObject.ObjectClass};
      "AccessRequest.Objects"      = $objectMatches
      "AccessRequest.PropertySets" = $propertySetMatches
      "AccessRequest.Properties"   = $propertyMatches
      "AccessRequest.Mask"         = [System.DirectoryServices.ActiveDirectoryRights]$_.Properties[10].Value
      "Result"                     = $InputObject.KeywordsDisplayNames[0] -replace "^Audit ",""
    }
  }
}

Export-ModuleMember -Function Get-DSSchemaGuid,
                              Get-DSRightsGuid,
                              Get-DSPropertySetMembers,
                              Get-DSAclRule,
                              Format-DSAclRule,
                              Add-DSOUAccess,
                              Enable-DSAccessAudit,
                              Disable-DSAccessAudit,
                              Get-DSAccessEvent,
                              Export-DSAccessEvent,
                              Format-DSAccessEvent