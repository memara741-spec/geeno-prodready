import { BrowserRouter, Link, Route, Routes } from 'react-router-dom';
import Account from './pages/Account';
import Feed from './pages/Feed';
import Privacy from './pages/Privacy';

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Feed />} />
        <Route path="/account" element={<Account />} />
        <Route path="/privacy" element={<Privacy />} />
        <Route path="*" element={<p>Page not found. <Link to="/">Go home</Link></p>} />
      </Routes>
      <footer>
        <Link to="/privacy">Privacy</Link> · <a href="mailto:support@notely.example">Contact support</a>
      </footer>
    </BrowserRouter>
  );
}
