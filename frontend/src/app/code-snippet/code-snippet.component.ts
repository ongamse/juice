/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { CodeSnippetService, type CodeSnippet } from '../Services/code-snippet.service'
import { CookieService } from 'ngy-cookie'
import { ChallengeService } from '../Services/challenge.service'
import { VulnLinesService, type result } from '../Services/vuln-lines.service'
import { Component, type OnInit, inject } from '@angular/core'

import { MAT_DIALOG_DATA, MatDialogTitle, MatDialogContent, MatDialogActions, MatDialogClose } from '@angular/material/dialog'
import { UntypedFormControl, FormsModule } from '@angular/forms'
import { ConfigurationService } from '../Services/configuration.service'
import { type ThemePalette } from '@angular/material/core'
import { MatIconButton, MatButtonModule } from '@angular/material/button'
import { MatInputModule } from '@angular/material/input'
import { MatFormFieldModule, MatLabel } from '@angular/material/form-field'

import { MatCardModule } from '@angular/material/card'
import { MatIconModule } from '@angular/material/icon'
import { TranslateModule } from '@ngx-translate/core'
import { CodeAreaComponent } from '../code-area/code-area.component'

import { MatTabGroup, MatTab, MatTabLabel } from '@angular/material/tabs'

enum ResultState {
  Undecided,
  Right,
  Wrong,
}

export interface Solved {
  findIt: boolean
}

@Component({
  selector: 'code-snippet',
  templateUrl: './code-snippet.component.html',
  styleUrls: ['./code-snippet.component.scss'],
  host: { class: 'code-snippet' },
  imports: [MatDialogTitle, MatDialogContent, MatTabGroup, MatTab, CodeAreaComponent, TranslateModule, MatTabLabel, MatIconModule, MatDialogActions, MatCardModule, MatFormFieldModule, MatInputModule, FormsModule, MatIconButton, MatButtonModule, MatDialogClose]
})
export class CodeSnippetComponent implements OnInit {
  dialogData = inject(MAT_DIALOG_DATA);
  private readonly configurationService = inject(ConfigurationService);
  private readonly codeSnippetService = inject(CodeSnippetService);
  private readonly vulnLinesService = inject(VulnLinesService);
  private readonly challengeService = inject(ChallengeService);
  private readonly cookieService = inject(CookieService);

  public snippet: CodeSnippet = null
  public selectedLines: number[]
  public tab: UntypedFormControl = new UntypedFormControl(0)
  public lock: ResultState = ResultState.Undecided
  public result: ResultState = ResultState.Undecided
  public hint: string = null
  public solved: Solved = { findIt: false }
  public showFeedbackButtons = true

  ngOnInit (): void {
    this.configurationService.getApplicationConfiguration().subscribe({
      next: (config) => {
        this.showFeedbackButtons = config.challenges.showFeedbackButtons
      },
      error: (err) => { console.log(err) }
    })

    this.codeSnippetService.get(this.dialogData.key).subscribe({
      next: (snippet) => {
        this.snippet = snippet
        this.solved.findIt = false
        if (this.dialogData.codingChallengeStatus >= 1) {
          this.result = ResultState.Right
          this.lock = ResultState.Right
          this.solved.findIt = true
        }
      },
      error: (err) => {
        this.snippet = { snippet: err.error }
      }
    })
  }

  addLine = (lines: number[]) => {
    this.selectedLines = lines
  }

  toggleTab = (event: number) => {
    this.tab.setValue(event)
    this.result = ResultState.Undecided
    if (event === 0) {
      if (this.solved.findIt) this.result = ResultState.Right
    }
  }

  checkLines = () => {
    this.vulnLinesService.check(this.dialogData.key, this.selectedLines).subscribe((verdict: result) => {
      this.setVerdict(verdict.verdict)
      this.hint = verdict.hint
    })
  }

  lockIcon (): string {
    switch (this.lock) {
      case ResultState.Right:
        return 'lock_open'
      case ResultState.Wrong:
        return 'lock'
      case ResultState.Undecided:
        return 'lock'
    }
  }

  lockColor (): ThemePalette {
    switch (this.lockIcon()) {
      case 'lock_open':
        return 'accent'
      case 'lock':
        return 'warn'
    }
  }

  setVerdict = (verdict: boolean) => {
    if (this.result === ResultState.Right) return
    if (verdict) {
      if (this.tab.value === 0) {
        this.solved.findIt = true
        this.challengeService.continueCodeFindIt().subscribe({
          next: (continueCode) => {
            if (!continueCode) {
              throw (new Error('Received invalid continue code from the server!'))
            }
            const expires = new Date()
            expires.setFullYear(expires.getFullYear() + 1)
            this.cookieService.put('continueCodeFindIt', continueCode, { expires })
          },
          error: (err) => { console.log(err) }
        })
      }
      this.result = ResultState.Right
      this.lock = ResultState.Right
      import('../../confetti').then(module => {
        module.shootConfetti()
      })
    } else {
      this.result = ResultState.Wrong
    }
  }

  resultIcon (): string {
    switch (this.result) {
      case ResultState.Right:
        return 'check'
      case ResultState.Wrong:
        return 'clear'
      default:
        return 'send'
    }
  }

  resultColor (): ThemePalette {
    switch (this.resultIcon()) {
      case 'check':
        return 'accent'
      case 'clear':
        return 'warn'
    }
  }
}
