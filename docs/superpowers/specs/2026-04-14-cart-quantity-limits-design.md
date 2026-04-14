# Cart Quantity Limits Design

## Goal

Limit each basket item to a valid quantity range before it is added to or updated in a user's basket.

The accepted range is 1 to 5 items per product, and the requested quantity must still be available in stock.

## Scope

This change applies to the existing basket item API endpoints:

- `POST /api/BasketItems`
- `PUT /api/BasketItems/:id`

It does not change checkout, product catalog data, translations, or challenge definitions.

## Current Behavior

`routes/basketItems.ts` already routes basket item creation and updates through `quantityCheck()`. That helper checks product stock and product-specific `limitPerUser` values.

The API currently rejects quantities above a product-specific limit and quantities above stock. It does not explicitly reject zero or negative quantities, and products without a `limitPerUser` can accept quantities above 5 as long as stock is available.

## Proposed Behavior

The backend will enforce a general quantity range in `quantityCheck()`:

- Reject `quantity < 1` with HTTP 400.
- Reject `quantity > 5` with HTTP 400.
- Reject quantities above available stock with the existing out-of-stock response.
- Accept quantities from 1 to 5 when stock is available.

The "more than 5" response should reuse the existing "You can order only up to {{quantity}} items of this product." message with `quantity` set to `5`.

## Architecture

The rule belongs in `routes/basketItems.ts` because both create and update paths already call `quantityCheck()` before saving. Keeping the validation there gives the API one authoritative rule for normal UI requests and direct API calls.

The frontend basket component can keep its current behavior. It already prevents the decrement button from sending values below 1 during normal use, and backend validation will handle direct API requests or any future client-side gaps.

## Tests

Update `test/api/basketItemApiSpec.ts` to cover:

- Creating a basket item with `quantity: 0` is rejected.
- Creating a basket item with a negative quantity is rejected.
- Creating a basket item with `quantity: 6` is rejected.
- Updating a basket item to `quantity: 0` is rejected.
- Updating a basket item to `quantity: 6` is rejected.
- Creating or updating a basket item with `quantity: 5` succeeds when stock is available.
- Existing out-of-stock behavior remains rejected.

## Verification

Run the focused basket item API tests after implementation. Because this touches challenge-adjacent basket behavior, run the Refactoring Safety Net if the change is detected as affecting challenge code.
