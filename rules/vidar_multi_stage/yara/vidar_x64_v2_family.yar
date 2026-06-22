import "pe"

rule Vidar_x64_v2_family
{
    meta:
        description = "Vidar x64 2.x unpacked payload"
        author      = "Gianluca Tiepolo"
        date        = "2026-06-20"
        family      = "Vidar"
        version     = "2.x"
        arch        = "x86-64"
        scope       = "unpacked payload"
        reference_1 = "725344564a8c9b0a033e9a5d41369fae5b8503d36e87002e7c064eface927e7b"
        reference_2 = "debbb3b4fdd9107deec64c46b453b988c5b51a99e006f2c6d1c804b5e2a33991"
        
    strings:
        /*
         * Shared 4-argument bytecode-VM decoder setup
         */
        $vm_setup = {
            44 89 4C 24 20
            4C 89 44 24 18
            89 54 24 10
            48 89 4C 24 08
            48 83 EC 68
            E8 ?? ?? ?? ??
            E8 ?? ?? ?? ??
            25 FF 00 00 00
            88 44 24 30
            C6 44 24 31 00
            48 8B 44 24 70
            48 89 44 24 38
            8B 44 24 78
            89 44 24 40
            C7 44 24 44 00 00 00 00
        }

        /*
         * Stable VM dispatch loop
         */
        $vm_dispatch = {
            8B 44 24 40 39 44 24 44 73 4F
            8B 44 24 50 39 44 24 54 73 45
            8B 44 24 44 48 8B 4C 24 38 8A 04 01
            88 44 24 20 8B 44 24 44 FF C0 89 44 24 44
            0F B6 44 24 20
            48 8D 0D ?? ?? ?? ??
            48 8B 04 C1 48 89 44 24 28
            48 83 7C 24 28 00 75 02 EB 0C
            48 8D 4C 24 30 FF 54 24 28 90 EB A7
            48 83 C4 68 C3
        }

        /*
         * Embedded-config XOR decoder
         */
        $config_xor_loop = {
            4C 8B C9 4C 2B CA 4C 8B C2 49 F7 D8
            [0-64]
            4B 8D 04 18 48 F7 F7
            8A 0C 32 41 8A 03 32 C8 43 88 0C 19
            49 FF C3 4B 8D 04 18 49 3B C2 72 ??
        }

    condition:
        uint16(0) == 0x5A4D and
        pe.machine == pe.MACHINE_AMD64 and
        pe.number_of_imported_functions == 0 and
        pe.sections.len() >= 4 and pe.sections.len() <= 6 and
        filesize > 800KB and filesize < 1500KB and
        for any i in (0..pe.sections.len() - 1): (
            pe.sections[i].name == ".data" and
            pe.sections[i].virtual_size > 0x100000 and
            pe.sections[i].raw_data_size < 0x4000
        ) and
        all of them
}
