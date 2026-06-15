import "pe"
import "math"

rule vidar_turb00_payload {
	meta:
		description = "Vidar turb00 campaign — unpacked stealer payload"
		author      = "Gianluca Tiepolo"
		reference   = "https://mrtiepolo.medium.com"
		date        = "2026-06-15"
		hash1       = "725344564a8c9b0a033e9a5d41369fae5b8503d36e87002e7c064eface927e7b"
	strings:
		// custom FNV-1a constants
		$fnv_basis = { 85 8d ff 3a }
		$fnv_prime = { bb 06 00 01 }
		// string-decoder VM init constant 0x311b7f33
		$vm_init   = { 33 7f 1b 31 }
		// first 32 bytes of the 256-byte string-VM S-box, near-unique
		$sbox      = {
			cc ea 32 c5 f3 62 05 8e 12 0b e3 ca 44 4c f9 bf
			52 06 b3 fc b6 00 0f 7e 15 c3 6a 86 ac 8b 89 82
		}
		// hash-resolved API dwords
		$h1        = { 4f fb 93 a4 }  // CryptUnprotectData
		$h2        = { 14 36 82 45 }  // WinHttpSendRequest
		$h3        = { a3 68 5a 56 }  // CreateRemoteThread
		$h4        = { 66 59 ea d7 }  // BitBlt
	condition:
		// the S-box alone is essentially unique; otherwise require the hash engine + APIs
		$sbox
		or (all of ($fnv_*) and $vm_init and 2 of ($h*))
}

rule vidar_turb00_go_loader {
	meta:
		description = "Vidar turb00 campaign — delivered Go crypter/loader"
		author      = "Gianluca Tiepolo"
		reference   = "https://mrtiepolo.medium.com"
		date        = "2026-06-15"
		hash1       = "f332b8851b0137ab7fc02a7c64a8b82e62e37b61fc5abf588f25c9797b7ab005"
	strings:
		$gobuild = "Go build ID: \""
		// one code sequence common to all sampled family loaders
		$code    = {
			2d 00 48 85 f6 75 0c 48 be ff ff ff ff ff ff ff 7f
			eb 40 48 83 fe 01 75 04 31 f6 eb 36 48 89 44 24 30
			48 89 5c 24 38 48 89 4c 24 40 48 89 54 24
		}
	condition:
		uint16(0) == 0x5a4d and
		pe.machine == pe.MACHINE_AMD64 and
		filesize > 3000KB and filesize < 3700KB and
		$gobuild and $code and
		// embedded encrypted payload: a large high-entropy region must be present
		math.entropy(0x150000, 0x80000) >= 7.2
}
