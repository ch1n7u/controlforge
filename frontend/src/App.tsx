import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import { AuthProvider, RequireAuth } from './auth/AuthProvider'
import { Layout } from './components/Layout'
import { AuditPage } from './pages/AuditPage'
import { ControlDetailPage } from './pages/ControlDetailPage'
import { ControlsPage } from './pages/ControlsPage'
import { DashboardPage } from './pages/DashboardPage'
import { EvidenceDetailPage } from './pages/EvidenceDetailPage'
import { EvidencePage } from './pages/EvidencePage'
import { FindingDetailPage } from './pages/FindingDetailPage'
import { FindingsPage } from './pages/FindingsPage'
import { LoginPage } from './pages/LoginPage'
import { NewTargetPage } from './pages/NewTargetPage'
import { NewTestPage } from './pages/NewTestPage'
import { RunDetailPage } from './pages/RunDetailPage'
import { RunsPage } from './pages/RunsPage'
import { ScopeDetailPage } from './pages/ScopeDetailPage'
import { ScopesPage } from './pages/ScopesPage'
import { SettingsPage } from './pages/SettingsPage'
import { TargetDetailPage } from './pages/TargetDetailPage'
import { TargetsPage } from './pages/TargetsPage'
import { TestDetailPage } from './pages/TestDetailPage'
import { TestsPage } from './pages/TestsPage'

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route
            path="/"
            element={
              <RequireAuth>
                <Layout />
              </RequireAuth>
            }
          >
            <Route index element={<Navigate to="/overview" replace />} />
            <Route path="overview" element={<DashboardPage />} />
            <Route path="controls" element={<ControlsPage />} />
            <Route path="controls/:id" element={<ControlDetailPage />} />
            <Route path="targets" element={<TargetsPage />} />
            <Route path="targets/new" element={<NewTargetPage />} />
            <Route path="targets/:id" element={<TargetDetailPage />} />
            <Route path="scopes" element={<ScopesPage />} />
            <Route path="scopes/:id" element={<ScopeDetailPage />} />
            <Route path="tests" element={<TestsPage />} />
            <Route path="tests/new" element={<NewTestPage />} />
            <Route path="tests/:id" element={<TestDetailPage />} />
            <Route path="runs" element={<RunsPage />} />
            <Route path="runs/:id" element={<RunDetailPage />} />
            <Route path="findings" element={<FindingsPage />} />
            <Route path="findings/:id" element={<FindingDetailPage />} />
            <Route path="evidence" element={<EvidencePage />} />
            <Route path="evidence/:id" element={<EvidenceDetailPage />} />
            <Route path="audit" element={<AuditPage />} />
            <Route path="settings" element={<SettingsPage />} />
            <Route path="*" element={<Navigate to="/overview" replace />} />
          </Route>
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  )
}
