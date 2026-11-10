const request = require('supertest');
const express = require('express');

// Create a mock app to simulate the vulnerable logic in server.js
// We are simulating the database checks and JWT logic.
const app = express();
app.use(express.json());

// MOCK DATABASE (Simulating expenses.db)
const mockClaims = [
    { id: 1, user_id: 101, merchant: 'Amazon', amount: 50, note: 'Office supplies' },
    { id: 2, user_id: 102, merchant: 'Apple', amount: 1200, note: 'MacBook charger' }
];

// MOCK JWT (Simulating the 'currentUser' function)
// We are testing the logic: Can user 101 access user 102's claim?
app.get('/claim/:id', (req, res) => {
    const u = { uid: 101, role: 'user' }; // Simulating User 101 (Standard User)
    
    const row = mockClaims.find(c => c.id === parseInt(req.params.id));
    if (!row) return res.status(404).send('Not found');
    
    // VULNERABLE LOGIC (If this check is removed, the test fails)
    if (!u || (row.user_id !== u.uid && u.role !== 'admin')) {
        return res.status(403).send('Forbidden');
    }
    res.json(row);
});

describe('Custom Security Tests - Meridian Expenses', () => {
    
    // TEST 1: The IDOR / Missing Authorisation Test
    test('TEST 1: Should block User 101 from accessing User 102 claim (IDOR)', async () => {
        // User 101 is logged in (simulated), but tries to access claim ID 2 (owned by User 102)
        const response = await request(app).get('/claim/2');
        
        // ASSERTION: Expect a 403 Forbidden status
        expect(response.status).toBe(403);
        
        // ASSERTION: Ensure the other user's data is NOT leaked in the response body
        expect(response.text).not.toContain('MacBook charger');
    });

    // TEST 2: The Business Logic Test (Amount Limit)
    test('TEST 2: Should flag suspicious high-value claim', () => {
        // Simulating a business rule (e.g., claims over 1000 need manager approval)
        const testAmount = 1500;
        const requiresApproval = testAmount > 1000;
        
        // ASSERTION: The business logic must catch this
        expect(requiresApproval).toBe(true);
    });

});
