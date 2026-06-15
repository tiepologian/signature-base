import "pe"
import "math"
import "vt"

rule vidar_turb00_loader_behaviour {
	meta:
		description = "Vidar turb00 campaign — delivered Go crypter/loader + actor-C2 behavior for LiveHunt"
		author      = "Gianluca Tiepolo"
		reference   = "https://mrtiepolo.medium.com"
		date        = "2026-06-15"
		hash1       = "f332b8851b0137ab7fc02a7c64a8b82e62e37b61fc5abf588f25c9797b7ab005"
	strings:
		$gobuild = "Go build ID: \""
	condition:
		// ---- static loader structure ----
		uint16(0) == 0x5a4d and
		pe.machine == pe.MACHINE_AMD64 and
		filesize > 3000KB and filesize < 3700KB and
		$gobuild and
		math.entropy(0x150000, 0x80000) >= 7.2 and

		// ---- dynamic confirmation via VT sandbox behaviour ----
		(
			(
				for any d in vt.behaviour.dns_lookups: (
					d.hostname matches /glamis[a-z]*rent/i or
					d.hostname matches /turbo88ku/i
				)
			)
			or
			(
				for any c in vt.behaviour.http_conversations: (
					c.url matches /:\/\/(srv|ggt|ffe)\.[a-z0-9.]*(turbo88ku|glamis)/i
				)
			)
			or
			(
				(
					for any d in vt.behaviour.dns_lookups: (
						d.hostname matches /telegram\.me/i
					)
				)
				and
				(
					for any d in vt.behaviour.dns_lookups: (
						d.hostname matches /steamcommunity\.com/i
					)
				)
			)
		)
}
