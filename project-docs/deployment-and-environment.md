# Deployment and Environment Setup

## Development Environment

- Node.js (version 16 or higher)
- npm or yarn package manager
- Environment variables for Spotify API credentials, OpenAI API key, and other secrets
- Local development with Next.js dev server

## Environment Variables

- `SPOTIFY_CLIENT_ID`
- `SPOTIFY_CLIENT_SECRET`
- `SPOTIFY_REDIRECT_URI`
- `OPENAI_API_KEY`
- `NEXT_PUBLIC_BASE_URL` (for frontend API calls)

## Deployment

- Recommended platform: Vercel (optimized for Next.js)
- Configure environment variables securely in the deployment platform
- Use serverless functions (Next.js API routes) for backend logic
- Enable HTTPS and secure headers
- Set up monitoring and logging for production environment

## Continuous Integration / Continuous Deployment (CI/CD)

- Use GitHub Actions or similar for automated testing and deployment
- Run linting, formatting, and tests on pull requests
- Deploy automatically on merge to main branch

## Local Setup Instructions

1. Clone the repository
2. Install dependencies with `npm install` or `yarn`
3. Create a `.env.local` file with required environment variables
4. Run the development server with `npm run dev` or `yarn dev`
5. Access the app at `http://localhost:3000`
