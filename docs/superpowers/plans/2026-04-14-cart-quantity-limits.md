# Cart Quantity Limits Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enforce basket item quantities from 1 to 5 while preserving the existing stock check.

**Architecture:** The backend remains the source of truth. Both `POST /api/BasketItems` and `PUT /api/BasketItems/:id` already pass through `quantityCheck()` in `routes/basketItems.ts`, so the new range rule goes there and the API tests document the behavior.

**Tech Stack:** TypeScript, Express route middleware, Sequelize models, Frisby/Jest API tests, npm scripts.

---

## File Structure

- Modify: `routes/basketItems.ts`
  - Add a local constant for the maximum basket item quantity.
  - Make update validation run when `quantity` is `0`.
  - Add early range checks inside `quantityCheck()` before stock checks.
- Modify: `test/api/basketItemApiSpec.ts`
  - Add failing tests for zero, negative, and above-maximum quantities.
  - Adjust existing helper data that currently creates quantities above 5.
  - Add positive coverage for `quantity: 5`.
- Use existing commands:
  - Focused API test: `npm run frisby -- test/api/basketItemApiSpec.ts`
  - Lint: `npm run lint`
  - Safety net if challenge-related snippets report changes: `npm run rsn`

---

### Task 1: Add POST Coverage For Quantity Range

**Files:**
- Modify: `test/api/basketItemApiSpec.ts`

- [ ] **Step 1: Add failing POST tests**

In the `/api/BasketItems` describe block, insert these tests after `POST new basket item`:

```ts
  it('POST new basket item with maximum allowed quantity', () => {
    return frisby.post(API_URL + '/BasketItems', {
      headers: authHeader,
      body: {
        BasketId: 2,
        ProductId: 3,
        quantity: 5
      }
    })
      .expect('status', 200)
      .expect('json', 'data', { quantity: 5 })
  })

  it('POST new basket item with zero quantity is forbidden', () => {
    return frisby.post(API_URL + '/BasketItems', {
      headers: authHeader,
      body: {
        BasketId: 2,
        ProductId: 3,
        quantity: 0
      }
    })
      .expect('status', 400)
      .expect('json', 'error', 'You must order at least 1 item of this product.')
  })

  it('POST new basket item with negative quantity is forbidden', () => {
    return frisby.post(API_URL + '/BasketItems', {
      headers: authHeader,
      body: {
        BasketId: 2,
        ProductId: 3,
        quantity: -1
      }
    })
      .expect('status', 400)
      .expect('json', 'error', 'You must order at least 1 item of this product.')
  })
```

- [ ] **Step 2: Run the focused API test to verify new tests fail**

Run:

```bash
npm run frisby -- test/api/basketItemApiSpec.ts
```

Expected result:

- The zero and negative quantity tests fail because the backend has not rejected those values yet.
- The command may also run the server through the existing Jest setup. If it cannot connect to `localhost:3000`, start the app in a separate shell with `npm start` and rerun the command.

- [ ] **Step 3: Commit POST test coverage**

Run:

```bash
git add test/api/basketItemApiSpec.ts
git commit -s -m "test: cover basket item quantity range on create"
```

---

### Task 2: Add PUT Coverage And Update Existing Test Fixtures

**Files:**
- Modify: `test/api/basketItemApiSpec.ts`

- [ ] **Step 1: Change existing tests that create quantities above 5 only as setup data**

Replace this test body:

```ts
  it('PUT update newly created basket item', () => {
    return frisby.post(API_URL + '/BasketItems', {
      headers: authHeader,
      body: {
        BasketId: 2,
        ProductId: 3,
        quantity: 3
      }
    })
      .expect('status', 200)
      .then(({ json }) => {
        return frisby.put(API_URL + '/BasketItems/' + json.data.id, {
          headers: authHeader,
          body: {
            quantity: 20
          }
        })
          .expect('status', 200)
          .expect('json', 'data', { quantity: 20 })
      })
  })
```

with:

```ts
  it('PUT update newly created basket item', () => {
    return frisby.post(API_URL + '/BasketItems', {
      headers: authHeader,
      body: {
        BasketId: 2,
        ProductId: 3,
        quantity: 3
      }
    })
      .expect('status', 200)
      .then(({ json }) => {
        return frisby.put(API_URL + '/BasketItems/' + json.data.id, {
          headers: authHeader,
          body: {
            quantity: 5
          }
        })
          .expect('status', 200)
          .expect('json', 'data', { quantity: 5 })
      })
  })
```

Then change setup quantities in later tests:

```ts
ProductId: 8,
quantity: 8
```

to:

```ts
ProductId: 8,
quantity: 5
```

Change:

```ts
ProductId: 9,
quantity: 9
```

to:

```ts
ProductId: 9,
quantity: 5
```

Change:

```ts
ProductId: 10,
quantity: 10
```

to:

```ts
ProductId: 10,
quantity: 5
```

- [ ] **Step 2: Add failing PUT tests for invalid low quantities**

Insert these tests after `PUT update newly created basket item`:

```ts
  it('PUT update basket item with zero quantity is forbidden', () => {
    return frisby.post(API_URL + '/BasketItems', {
      headers: authHeader,
      body: {
        BasketId: 2,
        ProductId: 3,
        quantity: 1
      }
    })
      .expect('status', 200)
      .then(({ json }) => {
        return frisby.put(API_URL + '/BasketItems/' + json.data.id, {
          headers: authHeader,
          body: {
            quantity: 0
          }
        })
          .expect('status', 400)
          .expect('json', 'error', 'You must order at least 1 item of this product.')
      })
  })

  it('PUT update basket item with negative quantity is forbidden', () => {
    return frisby.post(API_URL + '/BasketItems', {
      headers: authHeader,
      body: {
        BasketId: 2,
        ProductId: 3,
        quantity: 1
      }
    })
      .expect('status', 200)
      .then(({ json }) => {
        return frisby.put(API_URL + '/BasketItems/' + json.data.id, {
          headers: authHeader,
          body: {
            quantity: -1
          }
        })
          .expect('status', 400)
          .expect('json', 'error', 'You must order at least 1 item of this product.')
      })
  })
```

- [ ] **Step 3: Keep the existing above-maximum test**

Leave this existing test in place because it already verifies `quantity: 6` is rejected with the desired message:

```ts
  it('PUT update basket item with more than allowed quantity is forbidden', () => {
    return frisby.post(API_URL + '/BasketItems', {
      headers: authHeader,
      body: {
        BasketId: 2,
        ProductId: 1,
        quantity: 1
      }
    })
      .expect('status', 200)
      .then(({ json }) => {
        return frisby.put(API_URL + '/BasketItems/' + json.data.id, {
          headers: authHeader,
          body: {
            quantity: 6
          }
        })
          .expect('status', 400)
          .expect('json', 'error', 'You can order only up to 5 items of this product.')
      })
  })
```

- [ ] **Step 4: Run the focused API test to verify the new low-quantity tests fail**

Run:

```bash
npm run frisby -- test/api/basketItemApiSpec.ts
```

Expected result:

- The zero and negative PUT tests fail until backend validation is added.
- Tests whose setup quantities were changed to `5` should still reach the same endpoint behavior they were originally testing.

- [ ] **Step 5: Commit PUT test coverage**

Run:

```bash
git add test/api/basketItemApiSpec.ts
git commit -s -m "test: cover basket item quantity range on update"
```

---

### Task 3: Enforce Quantity Range In Backend

**Files:**
- Modify: `routes/basketItems.ts`

- [ ] **Step 1: Add the maximum quantity constant**

Add this below the `RequestWithRawBody` interface:

```ts
const maxBasketItemQuantity = 5
```

- [ ] **Step 2: Make update validation run for zero**

Replace this condition in `quantityCheckBeforeBasketItemUpdate()`:

```ts
      if (req.body.quantity) {
```

with:

```ts
      if (req.body.quantity !== undefined) {
```

This keeps updates that omit `quantity` on the existing path while ensuring `quantity: 0` is validated and rejected.

- [ ] **Step 3: Replace `quantityCheck()` with range-aware validation**

Replace the existing `quantityCheck()` function with:

```ts
async function quantityCheck (req: Request, res: Response, next: NextFunction, id: number, quantity: number) {
  const product = await QuantityModel.findOne({ where: { ProductId: id } })
  if (product == null) {
    throw new Error('No such product found!')
  }

  if (quantity < 1) {
    res.status(400).json({ error: res.__('You must order at least 1 item of this product.') })
    return
  }

  const quantityLimit = product.limitPerUser && !security.isDeluxe(req)
    ? Math.min(product.limitPerUser, maxBasketItemQuantity)
    : maxBasketItemQuantity

  if (quantity > quantityLimit) {
    res.status(400).json({ error: res.__('You can order only up to {{quantity}} items of this product.', { quantity: quantityLimit.toString() }) })
    return
  }

  if (product.quantity >= quantity) { // enough in stock?
    next()
  } else {
    res.status(400).json({ error: res.__('We are out of stock! Sorry for the inconvenience.') })
  }
}
```

This keeps product-specific limits for non-deluxe users, keeps deluxe bypass for product-specific limits, and still applies the global maximum of 5 to all users.

- [ ] **Step 4: Run the focused API test to verify it passes**

Run:

```bash
npm run frisby -- test/api/basketItemApiSpec.ts
```

Expected result:

- `test/api/basketItemApiSpec.ts` passes.

- [ ] **Step 5: Commit backend validation**

Run:

```bash
git add routes/basketItems.ts
git commit -s -m "fix: enforce basket item quantity limits"
```

---

### Task 4: Final Verification

**Files:**
- Read: `package.json`
- Read: `routes/basketItems.ts`
- Read: `test/api/basketItemApiSpec.ts`

- [ ] **Step 1: Run lint**

Run:

```bash
npm run lint
```

Expected result:

- ESLint and frontend lint commands pass.

- [ ] **Step 2: Run focused API tests**

Run:

```bash
npm run frisby -- test/api/basketItemApiSpec.ts
```

Expected result:

- All basket item API tests pass.

- [ ] **Step 3: Run broader API tests**

Run:

```bash
npm run frisby
```

Expected result:

- The Frisby API suite passes.

- [ ] **Step 4: Run RSN for challenge-adjacent basket behavior**

Run:

```bash
npm run rsn
```

Expected result:

- RSN passes without unexpected challenge snippet changes.
- If RSN reports a basket-related snippet mismatch, inspect the reported files before deciding whether the implementation or challenge cache needs adjustment.

- [ ] **Step 5: Review git status and commit any verification-only fixes**

Run:

```bash
git status --short --branch
```

Expected result:

- The branch is `feature/update-product-banner`.
- The worktree is clean after the test and implementation commits, unless generated coverage files are ignored or already untracked before this work.

If lint or RSN required a small code fix, commit it:

```bash
git add routes/basketItems.ts test/api/basketItemApiSpec.ts
git commit -s -m "test: finalize basket quantity limit coverage"
```

---

## Self-Review

- Spec coverage: The plan covers `POST /api/BasketItems`, `PUT /api/BasketItems/:id`, low quantity rejection, maximum quantity rejection, stock preservation, focused API tests, lint, and RSN.
- Scope: The plan does not change checkout, product catalog data, translations, challenge definitions, or frontend UI.
- Type consistency: The implementation uses existing `Request`, `Response`, `NextFunction`, `QuantityModel`, `security.isDeluxe(req)`, and `res.__()` patterns from `routes/basketItems.ts`.
