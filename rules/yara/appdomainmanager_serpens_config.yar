rule DotNet_AppDomainManager_Serpens_Value_Combination
{
    meta:
        author = "Skein LLC"
        description = "Flags value-aware .NET AppDomainManager hijack configuration"
        source = "Unit 42 Screening Serpens 2026 report"
        date = "2026-07-17"
        tlp = "CLEAR"

    strings:
        $manager_type = /appDomainManagerType\s*=\s*["'][^"']+["']/ nocase ascii
        $manager_assembly = /appDomainManagerAssembly\s*=\s*["'][^"']+["']/ nocase ascii
        $local_probe = /privatePath\s*=\s*["']\.[;"']/ nocase ascii

        $bad_etw = /<etwEnable[^>]+enabled\s*=\s*["']false["']/ nocase ascii
        $bad_strong_name = /<bypassTrustedAppStrongNames[^>]+enabled\s*=\s*["']true["']/ nocase ascii
        $bad_publisher = /<publisherPolicy[^>]+apply\s*=\s*["']no["']/ nocase ascii
        $bad_safemode = /<requiredRuntime[^>]+safemode\s*=\s*["']true["']/ nocase ascii

    condition:
        filesize < 2MB and
        uint16(0) != 0x5a4d and
        $manager_type and $manager_assembly and $local_probe and
        2 of ($bad_*)
}
