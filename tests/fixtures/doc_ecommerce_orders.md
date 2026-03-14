# StoreFront Orders API — Integration Guide

## Overview

StoreFront is an e-commerce order management system. This document describes the REST API for orders and invoices. All endpoints require a valid API key in the `X-API-Key` header.

## Authentication

- Every request must include `X-API-Key: <key>`. Keys are per merchant account.
- No documentation describes whether a merchant can access only their own orders or if object-level checks exist.

## Endpoints

### Orders

- **GET /store/v2/orders/{orderId}** — Returns order details: items, shipping address, status, total. Used by merchant dashboards.
- **GET /store/v2/orders/{orderId}/invoices** — Returns invoice records for the order. Pagination: `?page=&limit=`.
- **PATCH /store/v2/orders/{orderId}** — Update order status (e.g. shipped, cancelled). Documentation does not state that the caller must be the order owner or the assigned merchant.

### Invoices

- **GET /store/v2/invoices/{invoiceId}** — Returns a single invoice (PDF link, amount, line items). Requires API key. No mention of checking that the invoice belongs to the same merchant as the key.

## Data Model

- **Order** — orderId, merchantId, status, createdAt, items[].
- **Invoice** — invoiceId, orderId, amount, pdfUrl.

## Security Note

The authorization section only says "valid API key required". There is no description of how the system ensures that a merchant with key K can only access orders/invoices for their merchantId.
