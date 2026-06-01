namespace BossMod.SigScannerCli;

internal static class KnownSignatures
{
    public static readonly SignatureEntry[] All =
    [
        new("BossMod\\Debug\\DebugMapEffect.cs", 11, "ScanText",
            "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 48 83 EC 20 8B FA 41 0F B7 E8"),

        new("BossMod\\Framework\\ActionManagerEx.cs", 101, "ScanText",
            "E8 ?? ?? ?? ?? EB 3D 8B 93 ?? ?? ?? ??", 212, 4),

        new("BossMod\\Framework\\ActionManagerEx.cs", 105, "ScanText",
            "E8 ?? ?? ?? ?? 48 8B CE E8 ?? ?? ?? ?? 48 3B C5", 86, 1),

        new("BossMod\\Framework\\MovementOverride.cs", 63, "GetStaticAddressFromSig",
            "F3 0F 11 0D ?? ?? ?? ?? 48 85 DB"),

        new("BossMod\\Framework\\MovementOverride.cs", 83, "ScanText",
            "E8 ?? ?? ?? ?? 84 C0 75 10 38 43 3C", 114, 1),

        new("BossMod\\Framework\\MovementOverride.cs", 84, "ScanText",
            "E8 ?? ?? ?? ?? 84 C0 75 03 88 47 3F", 180, 1),

        new("BossMod\\Framework\\MovementOverride.cs", 90, "HookAddress",
            "E8 ?? ?? ?? ?? 80 7B 3E 00 48 8D 3D", 496, 4),

        new("BossMod\\Framework\\MovementOverride.cs", 91, "HookAddress",
            "E8 ?? ?? ?? ?? 0F B6 0D ?? ?? ?? ?? B8", 228, 2),

        new("BossMod\\Framework\\MovementOverride.cs", 92, "HookAddress",
            "E8 ?? ?? ?? ?? 84 C0 74 09 84 DB 74 1A", 114, 2),

        new("BossMod\\Framework\\WorldStateGameSync.cs", 119, "HookFromSignature",
            "40 53 57 48 81 EC ?? ?? ?? ?? 48 8B FA 8B D1", 160, 2),

        new("BossMod\\Framework\\WorldStateGameSync.cs", 123, "HookFromSignature",
            "48 8B C4 44 88 40 18 89 48 08", 226, 3),

        new("BossMod\\Framework\\WorldStateGameSync.cs", 127, "HookFromSignature",
            "40 53 41 54 41 55 48 83 EC 40 83 3D ?? ?? ?? ?? ??", 473, 3),

        new("BossMod\\Framework\\WorldStateGameSync.cs", 131, "HookFromSignature",
            "E8 ?? ?? ?? ?? 0F B7 0B 83 E9 64", 284, 4),

        new("BossMod\\Framework\\WorldStateGameSync.cs", 136, "HookFromSignature",
            "48 83 EC 68 48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 44 24 ?? 0F 10 41 10", 94, 1),

        new("BossMod\\Framework\\WorldStateGameSync.cs", 140, "HookFromSignature",
            "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 48 83 EC 20 8B FA 41 0F B7 E8", 186, 4),

        new("BossMod\\Framework\\WorldStateGameSync.cs", 144, "ScanAllText",
            "40 55 41 57 48 83 EC ?? 48 83 B9"),

        new("BossMod\\Framework\\WorldStateGameSync.cs", 158, "HookFromSignature",
            "44 8B 09 4C 8D 41 34", 23, 1),

        new("BossMod\\Framework\\WorldStateGameSync.cs", 162, "HookFromSignature",
            "E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 0F B6 47 28", 77, 4),

        new("BossMod\\Framework\\WorldStateGameSync.cs", 166, "HookFromSignature",
            "40 53 48 83 EC 20 48 8B DA 48 8D 0D ?? ?? ?? ?? 8B 52 10 E8 ?? ?? ?? ?? 48 85 C0 74 1B", 56, 1),

        new("BossMod\\Framework\\WorldStateGameSync.cs", 170, "HookFromSignature",
            "E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? 0F B7 4F 10 48 8D 57 12 41 B8", 61, 3),

        new("BossMod\\Framework\\WorldStateGameSync.cs", 174, "HookFromSignature",
            "48 89 5C 24 ?? 57 48 83 EC 20 48 8B DA 0F B7 F9", 45, 2),

        new("BossMod\\Framework\\WorldStateGameSync.cs", 178, "ScanText",
            "E8 ?? ?? ?? ?? 44 0F 28 D8 45 0F 57 D2", 41, 1),

        new("BossMod\\Framework\\WorldStateGameSync.cs", 181, "HookFromSignature",
            "89 54 24 10 48 89 4C 24 ?? 53 56 57 41 55 41 57 48 83 EC 30 48 8B 99 ?? ?? ?? ??", 233, 4),

        new("BossMod\\Framework\\WorldStateGameSync.cs", 191, "HookFromSignature",
            "48 89 5C 24 ?? 57 48 83 EC 30 48 8B 05 ?? ?? ?? ?? 48 8B D9 41 0F B6 50 ??", 86, 2),

        new("BossMod\\Framework\\WorldStateGameSync.cs", 196, "HookFromSignature",
            "48 8B D1 48 8D 0D ?? ?? ?? ?? E9 ?? ?? ?? ?? CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC CC 40 53 56", 15, 1),

        new("BossMod\\Network\\OpcodeMap.cs", 25, "ScanText",
            "49 8B 40 10  4C 8B 50 38  41 0F B7 42 02  83 C0 ??  3D ?? ?? ?? ??  0F 87 ?? ?? ?? ??  4C 8D 1D ?? ?? ?? ??  48 98  45 8B 8C 83 ?? ?? ?? ??"),

        new("BossMod\\Network\\PacketInterceptor.cs", 77, "TryScanText",
            "E8 ?? ?? ?? ?? 84 C0 0F 85 ?? ?? ?? ?? 48 8D 4C 24 ?? FF 15", 19, 1),

        new("BossMod\\Network\\PacketInterceptor.cs", 78, "TryScanText",
            "E8 ?? ?? ?? ?? 84 C0 0F 85 ?? ?? ?? ?? 44 0F B6 64 24"),

        new("BossMod\\Network\\PacketInterceptor.cs", 85, "HookAddress",
            "48 89 5C 24 ?? 48 89 74 24 ?? 4C 89 64 24 ?? 55 41 56 41 57 48 8B EC 48 83 EC 70", 202, 4),

        new("BossMod\\QuestBattle\\QuestBattle.cs", 316, "ScanText",
            "E8 ?? ?? ?? ?? 41 B2 01 EB 39", 61, 1),

        new("XIVSlothComboX\\Core\\PluginAddressResolver.cs", 18, "ScanText",
            "40 53 48 83 EC 20 8B D9 48 8B 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 85 C0 74 1F"),

        new("XIVSlothComboX\\Data\\ActionWatching.cs", 517, "HookFromSignature",
            "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 48 81 EC ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 84 24 ?? ?? ?? ?? 48 8B E9 41 0F B7 D9"),

        new("XIVSlothComboX\\Services\\PartyTargetingService.cs", 22, "ScanText",
            "E8 ?? ?? ?? ?? 48 8B D8 48 85 C0 0F 85 ?? ?? ?? ?? 8D 4F DD"),

        new("XIVSlothComboX\\Core\\HookAddress.cs", 43, "HookAddressConst",
            "E8 ?? ?? ?? ?? 89 03 8B 03"),
    ];
}
