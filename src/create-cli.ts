import crypto from 'node:crypto'
import { cac } from 'cac'
import consola from 'consola'
import { bin, version } from '../package.json'
import type { Options } from './types'

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

function base32ToBuf(str: string) {
  let end = str.length
  while (str[end - 1] === '=') --end
  const cstr = (end < str.length ? str.substring(0, end) : str).toUpperCase()

  const buf = new ArrayBuffer(((cstr.length * 5) / 8) | 0)
  const arr = new Uint8Array(buf)
  let bits = 0
  let value = 0
  let index = 0

  for (let i = 0; i < cstr.length; i++) {
    const idx = ALPHABET.indexOf(cstr[i])
    if (idx === -1) throw new TypeError(`Invalid character found: ${ cstr[i] }`)
    value = (value << 5) | idx
    bits += 5
    if (bits >= 8) {
      bits -= 8
      arr[index++] = value >>> bits
    }
  }

  return arr
}

function uintToBuf(num: number) {
  const buf = new ArrayBuffer(8)
  const arr = new Uint8Array(buf)
  let acc = num
  for (let i = 7; i >= 0; i--) {
    if (acc === 0) break
    arr[i] = acc & 255
    acc -= arr[i]
    acc /= 256
  }
  return arr
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
      const counter = Math.floor(timestamp / 1000 / period)

      const key = base32ToBuf(secret)
      const message = uintToBuf(counter)
      const hmac = crypto.createHmac(algorithm, key)
      hmac.update(message)
      const digest = new Uint8Array(hmac.digest().buffer)

      const offset = digest[digest.byteLength - 1] & 15
      const otp = (
        ((digest[offset] & 127) << 24)
        | ((digest[offset + 1] & 255) << 16)
        | ((digest[offset + 3] & 255) << 8)
        | (digest[offset + 3] & 255)
      ) % 10 ** digits

      consola.log(String(otp).padStart(digits, '0'))
    })

  cli
    .help()
    .version(version)
    .parse(process.argv, { run: false })

  return cli
}
