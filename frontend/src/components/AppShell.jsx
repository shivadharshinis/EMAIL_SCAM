import { NavLink, Outlet } from 'react-router-dom'

const links = [
  { to: '/login', label: 'Login' },
  { to: '/register', label: 'Register' },
  { to: '/analyze', label: 'Analyze' },
  { to: '/cases', label: 'Cases' },
]

export default function AppShell() {
  return (
    <div className="min-h-screen bg-slate-50 text-slate-900">
      <header className="border-b border-slate-200 bg-white">
        <div className="mx-auto flex max-w-5xl items-center justify-between px-6 py-4">
          <div>
            <p className="text-sm font-semibold tracking-wide text-slate-500">
              SIH106 · AIML
            </p>
            <h1 className="text-lg font-semibold">Email Forensics</h1>
          </div>
          <nav className="flex gap-4 text-sm">
            {links.map((link) => (
              <NavLink
                key={link.to}
                to={link.to}
                className={({ isActive }) =>
                  isActive
                    ? 'font-medium text-indigo-600'
                    : 'text-slate-600 hover:text-slate-900'
                }
              >
                {link.label}
              </NavLink>
            ))}
          </nav>
        </div>
      </header>
      <main className="mx-auto max-w-5xl px-6 py-10">
        <Outlet />
      </main>
    </div>
  )
}
