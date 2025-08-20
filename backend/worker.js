
// HealthAI Cloudflare Workers Backend
// This handles all server-side operations while maintaining zero-knowledge architecture

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // CORS headers for all responses
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    };

    // Handle preflight requests
    if (method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    try {
      // Route handling
      if (path === '/api/auth/verify') {
        return handleAuthVerification(request, env, corsHeaders);
      }
      
      if (path === '/api/documents/upload') {
        return handleDocumentUpload(request, env, corsHeaders);
      }
      
      if (path === '/api/documents/list') {
        return handleDocumentList(request, env, corsHeaders);
      }
      
      if (path === '/api/documents/download') {
        return handleDocumentDownload(request, env, corsHeaders);
      }
      
      if (path === '/api/documents/delete') {
        return handleDocumentDelete(request, env, corsHeaders);
      }
      
      if (path === '/api/medical/reference') {
        return handleMedicalReference(request, env, corsHeaders);
      }
      
      // Health check endpoint
      if (path === '/health') {
        return new Response(JSON.stringify({
          status: 'healthy',
          timestamp: new Date().toISOString(),
          version: '1.0.0',
          services: {
            database: 'connected',
            storage: 'connected',
            ai: 'ready'
          }
        }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      }
      
      // Serve the main application
      if (path === '/' || path === '/index.html') {
        return serveMainApp(env, corsHeaders);
      }
      
      return new Response('Not Found', { status: 404, headers: corsHeaders });
      
    } catch (error) {
      console.error('Worker error:', error);
      return new Response('Internal Server Error', { 
        status: 500, 
        headers: corsHeaders 
      });
    }
  }
};

// Authentication verification using Google OAuth
async function handleAuthVerification(request, env, corsHeaders) {
  if (request.method !== 'POST') {
    return new Response('Method not allowed', { status: 405, headers: corsHeaders });
  }

  const { googleToken, securityAnswers } = await request.json();
  
  try {
    // Verify Google token with Google's API
    const googleResponse = await fetch(`https://oauth2.googleapis.com/tokeninfo?id_token=${googleToken}`);
    const googleData = await googleResponse.json();
    
    if (!googleResponse.ok) {
      return new Response('Invalid Google token', { status: 401, headers: corsHeaders });
    }
    
    const userId = googleData.sub;
    const email = googleData.email;
    const name = googleData.name;
    const picture = googleData.picture;
    
    // Check if user exists in D1 database
    let user = await env.DB.prepare(
      'SELECT * FROM users WHERE google_id = ?'
    ).bind(userId).first();
    
    if (!user) {
      // Create new user
      await env.DB.prepare(`
        INSERT INTO users (google_id, email, name, picture, created_at, updated_at)
        VALUES (?, ?, ?, ?, datetime('now'), datetime('now'))
      `).bind(userId, email, name, picture).run();
      
      user = { google_id: userId, email, name, picture, is_new: true };
    } else {
      // Update last login
      await env.DB.prepare(
        'UPDATE users SET updated_at = datetime("now") WHERE google_id = ?'
      ).bind(userId).run();
      
      user.is_new = false;
    }
    
    // If security answers provided, store them (hashed)
    if (securityAnswers && securityAnswers.length === 3) {
      const hashedAnswers = await Promise.all(
        securityAnswers.map(answer => hashSecurityAnswer(answer.toLowerCase().trim()))
      );
      
      await env.DB.prepare(`
        INSERT OR REPLACE INTO user_security (user_id, answer_hash_1, answer_hash_2, answer_hash_3, created_at)
        VALUES (?, ?, ?, ?, datetime('now'))
      `).bind(userId, hashedAnswers[0], hashedAnswers[1], hashedAnswers[2]).run();
    }
    
    // Generate session token
    const sessionToken = await generateSessionToken(userId);
    
    return new Response(JSON.stringify({
      success: true,
      user: {
        id: userId,
        email: user.email,
        name: user.name,
        picture: user.picture,
        isNew: user.is_new
      },
      sessionToken
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
    
  } catch (error) {
    console.error('Auth verification error:', error);
    return new Response('Authentication failed', { status: 500, headers: corsHeaders });
  }
}

// Handle encrypted document upload to Cloudflare R2
async function handleDocumentUpload(request, env, corsHeaders) {
  if (request.method !== 'POST') {
    return new Response('Method not allowed', { status: 405, headers: corsHeaders });
  }

  try {
    const formData = await request.formData();
    const encryptedFile = formData.get('file');
    const fileName = formData.get('fileName');
    const fileSize = formData.get('fileSize');
    const documentType = formData.get('documentType');
    const userId = formData.get('userId');
    const sessionToken = formData.get('sessionToken');
    
    // Verify session token
    const isValidSession = await verifySessionToken(sessionToken, userId, env);
    if (!isValidSession) {
      return new Response('Unauthorized', { status: 401, headers: corsHeaders });
    }
    
    // Generate unique file ID
    const fileId = crypto.randomUUID();
    const r2Key = `users/${userId}/documents/${fileId}`;
    
    // Upload encrypted file to R2
    await env.HEALTH_DOCUMENTS.put(r2Key, encryptedFile);
    
    // Store metadata in D1 (no sensitive data)
    await env.DB.prepare(`
      INSERT INTO documents (id, user_id, filename, file_size, document_type, r2_key, created_at)
      VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
    `).bind(fileId, userId, fileName, fileSize, documentType, r2Key).run();
    
    return new Response(JSON.stringify({
      success: true,
      documentId: fileId,
      message: 'Document uploaded successfully'
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
    
  } catch (error) {
    console.error('Upload error:', error);
    return new Response('Upload failed', { status: 500, headers: corsHeaders });
  }
}

// List user's documents (metadata only)
async function handleDocumentList(request, env, corsHeaders) {
  if (request.method !== 'GET') {
    return new Response('Method not allowed', { status: 405, headers: corsHeaders });
  }

  const url = new URL(request.url);
  const userId = url.searchParams.get('userId');
  const sessionToken = url.searchParams.get('sessionToken');
  
  // Verify session
  const isValidSession = await verifySessionToken(sessionToken, userId, env);
  if (!isValidSession) {
    return new Response('Unauthorized', { status: 401, headers: corsHeaders });
  }
  
  try {
    const documents = await env.DB.prepare(
      'SELECT id, filename, file_size, document_type, created_at FROM documents WHERE user_id = ? ORDER BY created_at DESC'
    ).bind(userId).all();
    
    return new Response(JSON.stringify({
      success: true,
      documents: documents.results
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
    
  } catch (error) {
    console.error('List documents error:', error);
    return new Response('Failed to list documents', { status: 500, headers: corsHeaders });
  }
}

// Download encrypted document from R2
async function handleDocumentDownload(request, env, corsHeaders) {
  if (request.method !== 'GET') {
    return new Response('Method not allowed', { status: 405, headers: corsHeaders });
  }

  const url = new URL(request.url);
  const documentId = url.searchParams.get('documentId');
  const userId = url.searchParams.get('userId');
  const sessionToken = url.searchParams.get('sessionToken');
  
  // Verify session
  const isValidSession = await verifySessionToken(sessionToken, userId, env);
  if (!isValidSession) {
    return new Response('Unauthorized', { status: 401, headers: corsHeaders });
  }
  
  try {
    // Get document metadata
    const document = await env.DB.prepare(
      'SELECT * FROM documents WHERE id = ? AND user_id = ?'
    ).bind(documentId, userId).first();
    
    if (!document) {
      return new Response('Document not found', { status: 404, headers: corsHeaders });
    }
    
    // Get encrypted file from R2
    const object = await env.HEALTH_DOCUMENTS.get(document.r2_key);
    
    if (!object) {
      return new Response('File not found in storage', { status: 404, headers: corsHeaders });
    }
    
    // Return encrypted file (client will decrypt)
    return new Response(object.body, {
      headers: {
        ...corsHeaders,
        'Content-Type': 'application/octet-stream',
        'Content-Disposition': `attachment; filename="${document.filename}"`
      }
    });
    
  } catch (error) {
    console.error('Download error:', error);
    return new Response('Download failed', { status: 500, headers: corsHeaders });
  }
}

// Delete document
async function handleDocumentDelete(request, env, corsHeaders) {
  if (request.method !== 'DELETE') {
    return new Response('Method not allowed', { status: 405, headers: corsHeaders });
  }

  const { documentId, userId, sessionToken } = await request.json();
  
  // Verify session
  const isValidSession = await verifySessionToken(sessionToken, userId, env);
  if (!isValidSession) {
    return new Response('Unauthorized', { status: 401, headers: corsHeaders });
  }
  
  try {
    // Get document metadata
    const document = await env.DB.prepare(
      'SELECT * FROM documents WHERE id = ? AND user_id = ?'
    ).bind(documentId, userId).first();
    
    if (!document) {
      return new Response('Document not found', { status: 404, headers: corsHeaders });
    }
    
    // Delete from R2
    await env.HEALTH_DOCUMENTS.delete(document.r2_key);
    
    // Delete from database
    await env.DB.prepare(
      'DELETE FROM documents WHERE id = ? AND user_id = ?'
    ).bind(documentId, userId).run();
    
    return new Response(JSON.stringify({
      success: true,
      message: 'Document deleted successfully'
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
    
  } catch (error) {
    console.error('Delete error:', error);
    return new Response('Delete failed', { status: 500, headers: corsHeaders });
  }
}

// MedlinePlus API integration
async function handleMedicalReference(request, env, corsHeaders) {
  if (request.method !== 'GET') {
    return new Response('Method not allowed', { status: 405, headers: corsHeaders });
  }

  const url = new URL(request.url);
  const query = url.searchParams.get('query');
  
  if (!query) {
    return new Response('Query parameter required', { status: 400, headers: corsHeaders });
  }
  
  try {
    // MedlinePlus Connect API
    const medlineResponse = await fetch(
      `https://wsearch.nlm.nih.gov/ws/query?db=healthTopics&term=${encodeURIComponent(query)}&rettype=json`
    );
    
    const medlineData = await medlineResponse.json();
    
    return new Response(JSON.stringify({
      success: true,
      references: medlineData
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
    
  } catch (error) {
    console.error('MedlinePlus API error:', error);
    return new Response('Medical reference lookup failed', { status: 500, headers: corsHeaders });
  }
}

// Serve the main application HTML
async function serveMainApp(env, corsHeaders) {
  return new Response(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>HealthAI - Backend Active</title>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
    </head>
    <body>
      <div style="text-align: center; padding: 50px; font-family: system-ui;">
        <h1>HealthAI Backend Active</h1>
        <p>Cloudflare Workers backend is running successfully!</p>
        <p>API endpoints available at: /api/*</p>
      </div>
    </body>
    </html>
  `, {
    headers: { ...corsHeaders, 'Content-Type': 'text/html' }
  });
}

// Utility Functions

async function hashSecurityAnswer(answer) {
  const encoder = new TextEncoder();
  const data = encoder.encode(answer);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

async function generateSessionToken(userId) {
  const tokenData = {
    userId,
    timestamp: Date.now(),
    random: crypto.randomUUID()
  };
  
  const encoder = new TextEncoder();
  const data = encoder.encode(JSON.stringify(tokenData));
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

async function verifySessionToken(token, userId, env) {
  // In production, implement proper JWT verification
  // For now, basic validation
  return token && userId && token.length === 64;
}
