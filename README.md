# Event Joining App Landing Page

A modern React-based landing page for event registration with file upload capabilities, built with a comprehensive tech stack for scalability and performance.

## 🚀 Tech Stack

### Frontend
- **React** - The foundation for building a dynamic landing page and form functionality
- **Vite** - Fast build tool and development server
- **React Router** - For handling navigation between pages (landing page, user input form, admin dashboard, etc.)
- **React Hook Form** - To easily handle form inputs like name, age, reason, etc., with validation
- **React Dropzone** - For handling file uploads like profile pictures and ID cards
- **Tailwind CSS** - For styling the landing page and form with a clean, responsive, and modern look

### Backend & Deployment
- **Vercel** - Deployment platform for hosting your React app and serverless backend functions
- **Vercel Serverless Functions** - For handling backend logic like form submission, user data storage, and CRUD functionality
- **Supabase** - Provides both the database and storage for file uploads (profile picture and ID card)
- **PostgreSQL** - For storing the user data (name, age, reason, status, etc.)
- **Supabase Storage** - For storing the profile picture and ID card securely

## 📁 Project Structure

```
event-joining-app/
├── src/
│   ├── components/
│   │   ├── ui/           # Reusable UI components
│   │   ├── forms/        # Form-related components
│   │   └── layout/       # Layout components
│   ├── pages/            # Page components
│   ├── hooks/            # Custom React hooks
│   ├── utils/            # Utility functions
│   ├── api/              # API integration
│   ├── assets/           # Static assets
│   └── styles/           # Additional styles
├── api/                  # Vercel serverless functions
├── public/               # Public assets
└── ...
```

## 🛠️ Setup Instructions

### Prerequisites
- Node.js (v18 or higher)
- npm or yarn
- Git

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd event-joining-app
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Environment Setup**
   - Copy `.env.example` to `.env`
   - Fill in your Supabase credentials:
     ```env
     VITE_SUPABASE_URL=your_supabase_project_url
     VITE_SUPABASE_ANON_KEY=your_supabase_anon_key
     ```

4. **Start development server**
   ```bash
   npm run dev
   ```

### Supabase Setup

1. Create a new Supabase project at [supabase.com](https://supabase.com)
2. Set up your database tables for user data
3. Configure storage buckets for file uploads
4. Copy your project URL and anon key to the `.env` file

### Deployment

1. **Deploy to Vercel**
   ```bash
   npm install -g vercel
   vercel
   ```

2. **Configure environment variables in Vercel dashboard**
   - Add your Supabase credentials
   - Set up any additional environment variables

## 🎯 Features

- **Responsive Landing Page** - Modern, mobile-first design
- **User Registration Form** - With validation and file upload
- **File Upload Support** - Profile pictures and ID cards
- **Form Validation** - Client-side and server-side validation
- **Database Integration** - Secure data storage with Supabase
- **Serverless Backend** - Scalable API endpoints with Vercel Functions

## 📝 Development Guidelines

- Follow React best practices and hooks patterns
- Use Tailwind CSS for consistent styling
- Implement proper error handling and loading states
- Ensure responsive design across all devices
- Write clean, maintainable code with proper documentation

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License.
