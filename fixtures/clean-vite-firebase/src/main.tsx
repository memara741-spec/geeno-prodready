import * as Sentry from '@sentry/react';
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import App from './App';

Sentry.init({ dsn: import.meta.env.VITE_SENTRY_DSN, sendDefaultPii: false });

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <Sentry.ErrorBoundary fallback={<p>Something went wrong. Reload the page to try again.</p>}>
      <App />
    </Sentry.ErrorBoundary>
  </StrictMode>,
);
