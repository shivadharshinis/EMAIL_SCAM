import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import AppShell from './components/AppShell.jsx'
import Analyze from './pages/Analyze.jsx'
import Cases from './pages/Cases.jsx'
import Investigation from './pages/Investigation.jsx'
import Login from './pages/Login.jsx'
import Register from './pages/Register.jsx'

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<AppShell />}>
          <Route path="/" element={<Navigate to="/analyze" replace />} />
          <Route path="/login" element={<Login />} />
          <Route path="/register" element={<Register />} />
          <Route path="/analyze" element={<Analyze />} />
          <Route path="/cases" element={<Cases />} />
          <Route path="/investigation/:id?" element={<Investigation />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}
