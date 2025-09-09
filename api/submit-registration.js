import { createClient } from '@supabase/supabase-js';

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY
);

// Email validation regex
const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// Phone validation regex (basic international format)
const phoneRegex = /^[\+]?[1-9][\d]{0,15}$/;

// Validation function
function validateRegistrationData(data) {
  const errors = [];
  const { name, age, reason, email, phone } = data;

  // Required field validation
  if (!name || name.trim().length < 2) {
    errors.push('Name must be at least 2 characters long');
  }
  if (!age || isNaN(age) || age < 1 || age > 120) {
    errors.push('Age must be a valid number between 1 and 120');
  }
  if (!reason || reason.trim().length < 10) {
    errors.push('Reason must be at least 10 characters long');
  }
  if (!email || !emailRegex.test(email)) {
    errors.push('Please provide a valid email address');
  }
  if (phone && !phoneRegex.test(phone.replace(/[\s\-\(\)]/g, ''))) {
    errors.push('Please provide a valid phone number');
  }

  return errors;
}

export default async function handler(req, res) {
  // Enable CORS
  res.setHeader('Access-Control-Allow-Credentials', true);
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,PATCH,DELETE,POST,PUT');
  res.setHeader(
    'Access-Control-Allow-Headers',
    'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version, Authorization'
  );

  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { name, age, reason, email, phone } = req.body;

    // Validate input data
    const validationErrors = validateRegistrationData(req.body);
    if (validationErrors.length > 0) {
      return res.status(400).json({ 
        error: 'Validation failed',
        details: validationErrors
      });
    }

    // Check for duplicate email
    const { data: existingRegistration } = await supabase
      .from('registrations')
      .select('id, email')
      .eq('email', email.toLowerCase())
      .single();

    if (existingRegistration) {
      return res.status(409).json({ 
        error: 'A registration with this email already exists' 
      });
    }

    // Sanitize and prepare data
    const sanitizedData = {
      name: name.trim(),
      age: parseInt(age),
      reason: reason.trim(),
      email: email.toLowerCase().trim(),
      phone: phone ? phone.replace(/[\s\-\(\)]/g, '') : null,
      status: 'pending',
      created_at: new Date().toISOString()
    };

    // Insert user data into Supabase
    const { data, error } = await supabase
      .from('registrations')
      .insert([sanitizedData])
      .select();

    if (error) {
      console.error('Supabase error:', error);
      return res.status(500).json({ error: 'Failed to save registration' });
    }

    return res.status(201).json({ 
      success: true,
      message: 'Registration submitted successfully! You will receive a confirmation email shortly.',
      data: {
        id: data[0].id,
        name: data[0].name,
        email: data[0].email,
        status: data[0].status,
        created_at: data[0].created_at
      }
    });

  } catch (error) {
    console.error('Server error:', error);
    return res.status(500).json({ 
      error: 'Internal server error',
      message: 'Something went wrong. Please try again later.'
    });
  }
}