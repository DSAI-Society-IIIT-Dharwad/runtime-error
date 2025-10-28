export const GLOSSARY = {
  dns: 'Translates a domain name to an IP address.',
  connection: 'Packets exchanged between two endpoints within a short window.',
  hardwareId: 'Device hardware identifier used on local networks.',
} as const

export type GlossaryKey = keyof typeof GLOSSARY

export const glossaryTitle = (key: GlossaryKey) => GLOSSARY[key]
