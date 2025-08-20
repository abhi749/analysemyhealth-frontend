// HealthAI Backend - Cloudflare Worker
// Complete backend with OAuth callback support

export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        
        // CORS headers
        const corsHeaders = {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization',
            'Access-Control-Allow-Credentials': 'true'
        };

        // Handle CORS preflight requests
        if (request.method === 'OPTIONS') {
            return new Response(null, {
                status: 200,
                headers: corsHeaders
            });
        }

        try {
            // Health check endpoint
            if (url.pathname === '/' && request.method === 'GET') {
                return new Response(JSON.stringify({
                    status: 'healthy',
                    service: 'HealthAI Backend',
                    version: '1.0.0',
                    timestamp: new Date().toISOString()
                }), {
                    headers: { 'Content-Type': 'application/json', ...corsHeaders }
                });
            }

            // Google OAuth callback endpoint (NEW)
            if (url.pathname === '/auth/google/callback' && request.method === 'POST') {
                const { code, redirect_uri } = await request.json();
                
                if (!code) {
                    return new Response(JSON.stringify({ error: 'Missing authorization code' }), {
                        status: 400,
                        headers: { 'Content-Type': 'application/json', ...corsHeaders }
                    });
                }

                try {
                    // Exchange authorization code for access token
                    const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                        body: new URLSearchParams({
                            client_id: '674371229764-dbvid7j0lk44267igqkk87tg1onf4m2r.apps.googleusercontent.com',
                            client_secret: env.GOOGLE_CLIENT_SECRET,
                            code,
                            grant_type: 'authorization_code',
                            redirect_uri: redirect_uri || 'https://analysemyhealth.com/auth/callback'
                        })
                    });

                    if (!tokenResponse.ok) {
                        throw new Error('Failed to exchange code for token');
                    }

                    const tokens = await tokenResponse.json();
                    
                    // Get user information from Google
                    const userResponse = await fetch(`https://www.googleapis.com/oauth2/v2/userinfo?access_token=${tokens.access_token}`);
                    
                    if (!userResponse.ok) {
                        throw new Error('Failed to get user information');
                    }

                    const googleUser = await userResponse.json();
                    
                    // Generate session token
                    const sessionToken = await generateSessionToken(googleUser.id);
                    
                    // Store or update user in database
                    await storeUser(env.DB, {
                        google_id: googleUser.id,
                        email: googleUser.email,
                        name: googleUser.name,
                        picture: googleUser.picture,
                        last_login: new Date().toISOString()
                    });

                    // Return user data and session token
                    return new Response(JSON.stringify({
                        user: {
                            id: googleUser.id,
                            name: googleUser.name,
                            email: googleUser.email,
                            picture: googleUser.picture
                        },
                        token: sessionToken,
                        message: 'Authentication successful'
                    }), {
                        headers: { 'Content-Type': 'application/json', ...corsHeaders }
                    });

                } catch (error) {
                    console.error('OAuth callback error:', error);
                    return new Response(JSON.stringify({ 
                        error: 'Authentication failed',
                        details: error.message 
                    }), {
                        status: 500,
                        headers: { 'Content-Type': 'application/json', ...corsHeaders }
                    });
                }
            }

            // Original Google OAuth endpoint (for JWT tokens)
            if (url.pathname === '/auth/google' && request.method === 'POST') {
                const { credential } = await request.json();
                
                if (!credential) {
                    return new Response(JSON.stringify({ error: 'Missing credential' }), {
                        status: 400,
                        headers: { 'Content-Type': 'application/json', ...corsHeaders }
                    });
                }

                try {
                    // Verify the JWT token with Google
                    const verifyResponse = await fetch(
                        `https://oauth2.googleapis.com/tokeninfo?id_token=${credential}`
                    );

                    if (!verifyResponse.ok) {
                        throw new Error('Invalid credential');
                    }

                    const userInfo = await verifyResponse.json();
                    
                    // Verify the audience (client ID)
                    if (userInfo.aud !== '674371229764-dbvid7j0lk44267igqkk87tg1onf4m2r.apps.googleusercontent.com') {
                        throw new Error('Invalid audience');
                    }

                    // Generate session token
                    const sessionToken = await generateSessionToken(userInfo.sub);
                    
                    // Store or update user in database
                    await storeUser(env.DB, {
                        google_id: userInfo.sub,
                        email: userInfo.email,
                        name: userInfo.name,
                        picture: userInfo.picture,
                        last_login: new Date().toISOString()
                    });

                    return new Response(JSON.stringify({
                        user: {
                            id: userInfo.sub,
                            name: userInfo.name,
                            email: userInfo.email,
                            picture: userInfo.picture
                        },
                        token: sessionToken,
                        message: 'Authentication successful'
                    }), {
                        headers: { 'Content-Type': 'application/json', ...corsHeaders }
                    });

                } catch (error) {
                    console.error('Google auth error:', error);
                    return new Response(JSON.stringify({ 
                        error: 'Authentication failed',
                        details: error.message 
                    }), {
                        status: 401,
                        headers: { 'Content-Type': 'application/json', ...corsHeaders }
                    });
                }
            }

            // Document upload endpoint
            if (url.pathname === '/documents/upload' && request.method === 'POST') {
                const authHeader = request.headers.get('Authorization');
                if (!authHeader || !authHeader.startsWith('Bearer ')) {
                    return new Response(JSON.stringify({ error: 'Missing or invalid authorization' }), {
                        status: 401,
                        headers: { 'Content-Type': 'application/json', ...corsHeaders }
                    });
                }

                const token = authHeader.substring(7);
                const userId = await verifySessionToken(token);
                
                if (!userId) {
                    return new Response(JSON.stringify({ error: 'Invalid session token' }), {
                        status: 401,
                        headers: { 'Content-Type': 'application/json', ...corsHeaders }
                    });
                }

                try {
                    const formData = await request.formData();
                    const file = formData.get('document');
                    const type = formData.get('type') || 'health_report';

                    if (!file) {
                        return new Response(JSON.stringify({ error: 'No file provided' }), {
                            status: 400,
                            headers: { 'Content-Type': 'application/json', ...corsHeaders }
                        });
                    }

                    // Validate file type
                    if (file.type !== 'application/pdf') {
                        return new Response(JSON.stringify({ error: 'Only PDF files are allowed' }), {
                            status: 400,
                            headers: { 'Content-Type': 'application/json', ...corsHeaders }
                        });
                    }

                    // Validate file size (25MB limit)
                    if (file.size > 25 * 1024 * 1024) {
                        return new Response(JSON.stringify({ error: 'File size must be less than 25MB' }), {
                            status: 400,
                            headers: { 'Content-Type': 'application/json', ...corsHeaders }
                        });
                    }

                    // Generate unique file ID
                    const fileId = crypto.randomUUID();
                    const fileName = `${userId}/${fileId}.pdf`;

                    // Upload to Cloudflare R2
                    await env.HEALTH_DOCUMENTS.put(fileName, file.stream(), {
                        httpMetadata: {
                            contentType: 'application/pdf',
                        },
                        customMetadata: {
                            userId: userId,
                            originalName: file.name,
                            uploadDate: new Date().toISOString(),
                            type: type
                        }
                    });

                    // Store document metadata in database
                    await env.DB.prepare(`
                        INSERT INTO documents (id, user_id, filename, original_name, file_size, content_type, document_type, upload_date)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    `).bind(
                        fileId,
                        userId,
                        fileName,
                        file.name,
                        file.size,
                        file.type,
                        type,
                        new Date().toISOString()
                    ).run();

                    return new Response(JSON.stringify({
                        success: true,
                        document: {
                            id: fileId,
                            name: file.name,
                            size: file.size,
                            type: type,
                            uploadDate: new Date().toISOString()
                        },
                        message: 'Document uploaded successfully'
                    }), {
                        headers: { 'Content-Type': 'application/json', ...corsHeaders }
                    });

                } catch (error) {
                    console.error('Upload error:', error);
                    return new Response(JSON.stringify({ 
                        error: 'Upload failed',
                        details: error.message 
                    }), {
                        status: 500,
                        headers: { 'Content-Type': 'application/json', ...corsHeaders }
                    });
                }
            }

            // Get user documents
            if (url.pathname === '/documents' && request.method === 'GET') {
                const authHeader = request.headers.get('Authorization');
                if (!authHeader || !authHeader.startsWith('Bearer ')) {
                    return new Response(JSON.stringify({ error: 'Missing or invalid authorization' }), {
                        status: 401,
                        headers: { 'Content-Type': 'application/json', ...corsHeaders }
                    });
                }

                const token = authHeader.substring(7);
                const userId = await verifySessionToken(token);
                
                if (!userId) {
                    return new Response(JSON.stringify({ error: 'Invalid session token' }), {
                        status: 401,
                        headers: { 'Content-Type': 'application/json', ...corsHeaders }
                    });
                }

                try {
                    const documents = await env.DB.prepare(`
                        SELECT id, original_name, file_size, document_type, upload_date
                        FROM documents 
                        WHERE user_id = ? 
                        ORDER BY upload_date DESC
                    `).bind(userId).all();

                    return new Response(JSON.stringify({
                        documents: documents.results || []
                    }), {
                        headers: { 'Content-Type': 'application/json', ...corsHeaders }
                    });

                } catch (error) {
                    console.error('Documents fetch error:', error);
                    return new Response(JSON.stringify({ 
                        error: 'Failed to fetch documents',
                        details: error.message 
                    }), {
                        status: 500,
                        headers: { 'Content-Type': 'application/json', ...corsHeaders }
                    });
                }
            }

            // User profile endpoint
            if (url.pathname === '/user/profile' && request.method === 'GET') {
                const authHeader = request.headers.get('Authorization');
                if (!authHeader || !authHeader.startsWith('Bearer ')) {
                    return new Response(JSON.stringify({ error: 'Missing or invalid authorization' }), {
                        status: 401,
                        headers: { 'Content-Type': 'application/json', ...corsHeaders }
                    });
                }

                const token = authHeader.substring(7);
                const userId = await verifySessionToken(token);
                
                if (!userId) {
                    return new Response(JSON.stringify({ error: 'Invalid session token' }), {
                        status: 401,
                        headers: { 'Content-Type': 'application/json', ...corsHeaders }
                    });
                }

                try {
                    const user = await env.DB.prepare(`
                        SELECT google_id, email, name, picture, created_at, last_login
                        FROM users 
                        WHERE google_id = ?
                    `).bind(userId).first();

                    if (!user) {
                        return new Response(JSON.stringify({ error: 'User not found' }), {
                            status: 404,
                            headers: { 'Content-Type': 'application/json', ...corsHeaders }
                        });
                    }

                    return new Response(JSON.stringify({
                        user: {
                            id: user.google_id,
                            email: user.email,
                            name: user.name,
                            picture: user.picture,
                            memberSince: user.created_at,
                            lastLogin: user.last_login
                        }
                    }), {
                        headers: { 'Content-Type': 'application/json', ...corsHeaders }
                    });

                } catch (error) {
                    console.error('Profile fetch error:', error);
                    return new Response(JSON.stringify({ 
                        error: 'Failed to fetch profile',
                        details: error.message 
                    }), {
                        status: 500,
                        headers: { 'Content-Type': 'application/json', ...corsHeaders }
                    });
                }
            }

            // Default 404 response
            return new Response(JSON.stringify({ 
                error: 'Not found',
                path: url.pathname,
                method: request.method 
            }), {
                status: 404,
                headers: { 'Content-Type': 'application/json', ...corsHeaders }
            });

        } catch (error) {
            console.error('Worker error:', error);
            return new Response(JSON.stringify({ 
                error: 'Internal server error',
                details: error.message 
            }), {
                status: 500,
                headers: { 'Content-Type': 'application/json', ...corsHeaders }
            });
        }
    }
};

// Helper function to generate session tokens
async function generateSessionToken(userId) {
    const tokenData = {
        userId: userId,
        issued: Date.now(),
        expires: Date.now() + (7 * 24 * 60 * 60 * 1000) // 7 days
    };
    
    // Create a simple signed token (in production, use proper JWT)
    const tokenString = JSON.stringify(tokenData);
    const encoder = new TextEncoder();
    const data = encoder.encode(tokenString);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const signature = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    
    return btoa(tokenString) + '.' + signature;
}

// Helper function to verify session tokens
async function verifySessionToken(token) {
    try {
        const [tokenPart, signature] = token.split('.');
        const tokenString = atob(tokenPart);
        const tokenData = JSON.parse(tokenString);
        
        // Check if token is expired
        if (Date.now() > tokenData.expires) {
            return null;
        }
        
        // Verify signature
        const encoder = new TextEncoder();
        const data = encoder.encode(tokenString);
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const expectedSignature = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        
        if (signature !== expectedSignature) {
            return null;
        }
        
        return tokenData.userId;
    } catch (error) {
        console.error('Token verification error:', error);
        return null;
    }
}

// Helper function to store/update user in database
async function storeUser(db, userData) {
    try {
        // Try to insert new user, or update if exists
        await db.prepare(`
            INSERT INTO users (google_id, email, name, picture, created_at, last_login)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(google_id) DO UPDATE SET
                email = excluded.email,
                name = excluded.name,
                picture = excluded.picture,
                last_login = excluded.last_login
        `).bind(
            userData.google_id,
            userData.email,
            userData.name,
            userData.picture,
            userData.last_login, // created_at for new users
            userData.last_login
        ).run();
        
        console.log('User stored/updated successfully:', userData.email);
    } catch (error) {
        console.error('Error storing user:', error);
        throw error;
    }
}
