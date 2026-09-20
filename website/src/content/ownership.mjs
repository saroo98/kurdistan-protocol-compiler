export const ownership=[
  {
    "id": "device",
    "name": "Your phone",
    "owner": "You",
    "icon": "phone",
    "simple": "You choose the profile and grant Android VPN permission. A profile does not give its issuer control of your phone.",
    "technical": "Android grants VPN permission. Device-owned private material remains in protected local storage; the operating system controls its own always-on and lockdown settings.",
    "limit": "A compromised or unlocked device remains a separate risk. A VPN does not secure every app or permission on the phone."
  },
  {
    "id": "profile",
    "name": "The profile",
    "owner": "The profile issuer",
    "icon": "file",
    "simple": "A profile is the connection setup you add to the app. Its signed rules define access to a particular server.",
    "technical": "The signed artifact binds permitted runtime policy, validity and deployment identity. A recipient-sealed profile is intended for its enrolled device.",
    "limit": "The issuer can expire or revoke that access. A valid signature does not, by itself, tell you whether to trust the issuer."
  },
  {
    "id": "device-keys",
    "name": "Device keys",
    "owner": "Your device",
    "icon": "phone",
    "simple": "Device-bound keys open profiles made for this phone. They do not give the server operator remote control.",
    "technical": "The Android flow exports a public enrollment request. Private key material does not leave encrypted local storage except inside an encrypted backup.",
    "limit": "The public request is not a password. Backups and device compromise still need deliberate handling."
  },
  {
    "id": "authority",
    "name": "Server operator",
    "owner": "The person running the VPN server",
    "icon": "file",
    "simple": "The operator decides who may use the server. If you run the server, you can issue your own profiles.",
    "technical": "The deployment root is unique to its owner. Root private material is in a passphrase-encrypted recovery artifact; online issuer and relay keys have separate local custody.",
    "limit": "Control of a profile is not control of the phone. One independent deployment cannot revoke another deployment’s access."
  },
  {
    "id": "vps",
    "name": "The server",
    "owner": "The operator and hosting provider",
    "icon": "server",
    "simple": "The operator runs the VPN software. The hosting company controls the underlying VPS infrastructure. You decide whether to connect.",
    "technical": "kurd-node runs on an operator-controlled VPS. Host-level networking and resolver policy are outside the relay process’s authority.",
    "limit": "Self-hosting gives you operational control, not ownership of the hosting company’s equipment or guaranteed anonymity."
  },
  {
    "id": "project",
    "name": "The software",
    "owner": "Project maintainers and contributors",
    "icon": "settings",
    "simple": "Kurdistan VPN manages the connection on your phone according to the verified profile. It is software, not a remote device administrator.",
    "technical": "The public source contains the Kurd compiler, runtime, Android foundation and operator tooling. Review source and exact release provenance separately.",
    "limit": "Open source is not an independent audit. Build, distribution and operational evidence must be checked for each release."
  }
];
