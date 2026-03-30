describe('/#/score-board', () => {
  describe('challenge "scoreBoard"', () => {
    it('should be possible to access score board', () => {
      cy.visit('/#/score-board')
      cy.url().should('match', /\/score-board/)
      cy.expectChallengeSolved({ challenge: 'Score Board' })
    })
  })

  describe('challenge "continueCode"', () => {
    it('should be possible to solve the non-existent challenge #99', () => {
      cy.window().then(async () => {
        await fetch(
          `${Cypress.config('baseUrl')}/rest/continue-code/apply/69OxrZ8aJEgxONZyWoz1Dw4BvXmRGkM6Ae9M7k2rK63YpqQLPjnlb5V5LvDj`,
          {
            method: 'PUT',
            cache: 'no-cache',
            headers: {
              'Content-type': 'text/plain'
            }
          }
        )
      })
      cy.visit('/#/score-board')
      cy.expectChallengeSolved({ challenge: 'Imaginary Challenge' })
    })
  })
})

describe('/#/score-board repeat notification', () => {
  describe('repeat notification', () => {
    beforeEach(() => {
      cy.visit('/#/score-board')
      cy.expectChallengeSolved({ challenge: 'Score Board' })
    })

    it('should be possible on the new score board when flags are enabled in notifications', () => {
      cy.task('GetFromConfig', 'challenges.showSolvedNotifications').as(
        'showSolvedNotifications'
      )
      cy.task('GetFromConfig', 'ctf.showFlagsInNotifications').as(
        'showFlagsInNotifications'
      )

      cy.get('@showSolvedNotifications').then((showSolvedNotifications) => {
        cy.get('@showFlagsInNotifications').then((showFlagsInNotifications) => {
          if (showFlagsInNotifications) {
            cy.get('body').then(($body) => {
              const alertsBefore = $body.find('.challenge-solved-toast').length

              cy.get('[id="Score Board.repeatNotification"]').click()

              if (showSolvedNotifications) {
                cy.get('.challenge-solved-toast').should(($toasts) => {
                  expect($toasts.length).to.be.greaterThan(alertsBefore)
                })
              } else {
                cy.get('body').should(($updatedBody) => {
                  expect($updatedBody.find('.challenge-solved-toast').length).to.equal(alertsBefore)
                })
              }
            })
          } else {
            cy.get('[id="Score Board.repeatNotification"]').should('not.exist')
          }
        })
      })
    })
  })
})
