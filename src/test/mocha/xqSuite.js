'use strict'

const fs = require('fs')
const expect = require('chai').expect
const s = require('superagent')

const testRunnerLocalPath = 'src/test/mocha/runner.xq'

const pkg = JSON.parse(fs.readFileSync('package.json'))
const testCollection = '/test-' + pkg.name + '-' + pkg.version
const testRunner = testCollection + '/runner.xq'

const connectionOptions = {
  protocol: 'http',
  host: "localhost",
  port: "8080",
  path: "/exist/apps",
  basic_auth: {
    user: 'admin',
    pass: ''
  }
}

function connection (options) {
  const protocol = options.protocol ? options.protocol : 'http'
  const port = options.port ? ':' + options.port : ''
  const path = options.path.startsWith('/') ? options.path : '/' + options.path
  const prefix = `${protocol}://${options.host}${port}${path}`
  return (request) => {
    request.url = prefix + request.url
    request.auth(options.basic_auth.user, options.basic_auth.pass)
    return request
  }
}

describe('xqSuite', function () {
  let client, result

  before(done => {
    client = s.agent().use(connection(connectionOptions))
    const buffer = fs.readFileSync(testRunnerLocalPath)
    client
        .put(testRunner)
        .set('content-type', 'application/xquery')
        .set('content-length', buffer.length)
        .send(buffer)
        .then(_ => {
          return client.get(testRunner)
            .query({lib: pkg.name, version: pkg.version})
            .send()
        })
        .then(response => {
          if (response.body.error) {
            return Promise.reject(
              Error(response.body.error.description))
          }
          result = response.body.result
          done()
        })
        .catch(done)
  })

  it('should return 0 errors',
    ()=> expect(result.errors).to.equal(0))

  it('should return 0 failures',
    ()=> expect(result.failures).to.equal(0))

  it('should return 0 pending tests',
    ()=> expect(result.pending).to.equal(0))

  it('should have run 12 tests', 
    ()=> expect(result.tests).to.equal(12))

  it('should have finished in less than a second',
    ()=> expect(result.time).to.be.lessThan(1))

  after(done => {
    client.delete(testCollection)
      .send()
      .then(_ => done(), done)
  })

})
