describe('/rest/user/login', () => {
  describe('challenge "logInjection"', () => {
    it('should be possible to forge a log entry by injecting a newline and fake log line into the email field', () => {
      cy.request({
        method: 'POST',
        url: '/rest/user/login',
        body: {
          email: 'test@juice-sh.op\n192.168.1.1 - admin@juice-sh.op [forged] "GET /admin HTTP/1.1" 200',
          password: 'anything'
        },
        failOnStatusCode: false
      })
      cy.expectChallengeSolved({ challenge: 'Log Injection' })
    })
  })
})
