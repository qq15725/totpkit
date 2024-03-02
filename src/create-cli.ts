import crypto from 'node:crypto'
import { cac } from 'cac'
import consola from 'consola'
import { bin, version } from '../package.json'
import type { Options } from './types'

function base32Decode(base32String: string) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  const padding = '='

  let bits = ''
  let result = ''

  base32String = base32String.replace(new RegExp(padding, 'g'), '')

  for (let i = 0; i < base32String.length; i++) {
    const value = alphabet.indexOf(base32String[i].toUpperCase())
    bits += value.toString(2).padStart(5, '0')
  }

  for (let i = 0; i + 8 <= bits.length; i += 8) {
    const bytes = bits.substring(i, i + 8)
    result += String.fromCharCode(parseInt(bytes, 2))
  }

  return Buffer.from(result, 'binary')
}

export function createCli(_options: Options) {
  const cli = cac(Object.keys(bin)[0])

  cli
    .command('<secret>', 'Generate TOTP code')
    .action((secret, commandOptions) => {
      const {
        algorithm = 'sha1',
        digits = 6,
        period = 30,
        timestamp = Date.now(),
      } = commandOptions

      let time = Math.floor(timestamp / 1000 / period)

      const data = Buffer.alloc(8)
      for (let i = 0; i < 8; i++) {
        data[7 - i] = time & 0xFF
        time >>= 8
      }

      const hmac = crypto.createHmac(algorithm, base32Decode(secret))
      hmac.update(data)
      const hash = hmac.digest()

      const offset = hash[hash.length - 1] & 0xF
      const binCode = (hash[offset] & 0x7F) << 24
        | (hash[offset + 1] & 0xFF) << 16
        | (hash[offset + 2] & 0xFF) << 8
        | (hash[offset + 3] & 0xFF)

      const otp = binCode % 1000000

      consola.success(`ToTP code: ${ otp.toString().padStart(digits, '0') }`)
    })

  cli
    .help()
    .version(version)
    .parse(process.argv, { run: false })

  return cli
}
