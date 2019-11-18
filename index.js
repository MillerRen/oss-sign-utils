const hmacSha1 = require('crypto-js/hmac-sha1')
const base64 = require('crypto-js/enc-base64')
const isString = require('lodash.isstring')
const isArray = require('lodash.isarray')

/**
 *
 * @param {String} resourcePath
 * @param {Object} parameters
 * @return
 */
export function buildCanonicalizedResource (resourcePath, parameters) {
  let canonicalizedResource = `${resourcePath}`
  let separatorString = '?'

  if (isString(parameters) && parameters.trim() !== '') {
    canonicalizedResource += separatorString + parameters
  } else if (isArray(parameters)) {
    parameters.sort()
    canonicalizedResource += separatorString + parameters.join('&')
  } else if (parameters) {
    const compareFunc = (entry1, entry2) => {
      if (entry1[0] > entry2[0]) {
        return 1
      } else if (entry1[0] < entry2[0]) {
        return -1
      }
      return 0
    }
    const processFunc = (key) => {
      canonicalizedResource += separatorString + key
      if (parameters[key]) {
        canonicalizedResource += `=${parameters[key]}`
      }
      separatorString = '&'
    }
    Object.keys(parameters).sort(compareFunc).forEach(processFunc)
  }

  return canonicalizedResource
}

/**
 * @param {String} method
 * @param {String} resourcePath
 * @param {Object} headers
 * @param {Object} parameters
 * @param {String} expires
 * @return {String} canonicalString
 */
export function buildCanonicalString (method, resourcePath, headers = {}, parameters, expires) {
  const OSS_PREFIX = 'x-oss-'
  const ossHeaders = []
  const headersToSign = {}

  let signContent = [
    method.toUpperCase(),
    headers['Content-Md5'] || '',
    headers['Content-Type'] || headers['Content-Type'.toLowerCase()],
    expires || headers['x-oss-date']
  ]

  Object.keys(headers).forEach((key) => {
    const lowerKey = key.toLowerCase()
    if (lowerKey.indexOf(OSS_PREFIX) === 0) {
      headersToSign[lowerKey] = String(headers[key]).trim()
    }
  })

  Object.keys(headersToSign).sort().forEach((key) => {
    ossHeaders.push(`${key}:${headersToSign[key]}`)
  })

  signContent = signContent.concat(ossHeaders)

  signContent.push(this.buildCanonicalizedResource(resourcePath, parameters))

  return signContent.join('\n')
}

/**
 * @param {String} accessKeySecret
 * @param {String} canonicalString
 */
export function computeSignature (accessKeySecret, canonicalString) {
  return base64.stringify(hmacSha1(canonicalString, accessKeySecret))
}

/**
 * @param {String} accessKeyId
 * @param {String} accessKeySecret
 * @param {String} canonicalString
 */
export function authorization (accessKeyId, accessKeySecret, canonicalString) {
  return `OSS ${accessKeyId}:${this.computeSignature(accessKeySecret, canonicalString)}`
}
