#include "framework.h"
#include "PLPFidoExample.h"
#include "PLPFidoExampleDlg.h"

#include <memory>
#include <thread>

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

CPLPFidoExampleDlg::CPLPFidoExampleDlg(CWnd* pParent /*=nullptr*/)
  : CDialogEx(IDD_PLPFIDOEXAMPLE_DIALOG, pParent)
  , m_rpId(_T("security.mycompany.com"))
  , m_userName(_T("jane.dow@mycompany.com"))
  , m_fido(m_store)
{
}

void CPLPFidoExampleDlg::DoDataExchange(CDataExchange* pDX)
{
  CDialogEx::DoDataExchange(pDX);
  DDX_Control(pDX, IDC_COMBO_DEVICE, m_comboDevice);
  DDX_Control(pDX, IDC_EDIT_LOG, m_editLog);
  DDX_Text(pDX, IDC_EDIT_RPID, m_rpId);
  DDX_Text(pDX, IDC_EDIT_USER, m_userName);
  DDX_Text(pDX, IDC_EDIT_PIN, m_pin);
  DDX_Check(pDX, IDC_CHECK_RK, m_discoverable);
  DDX_Check(pDX, IDC_CHECK_ROAMING, m_roamingOnly);
  DDX_Check(pDX, IDC_CHECK_UV, m_requireUv);
}

BEGIN_MESSAGE_MAP(CPLPFidoExampleDlg, CDialogEx)
  ON_BN_CLICKED(IDC_BTN_REFRESH, &CPLPFidoExampleDlg::OnBnClickedRefresh)
  ON_BN_CLICKED(IDC_BTN_INFO, &CPLPFidoExampleDlg::OnBnClickedInfo)
  ON_BN_CLICKED(IDC_BTN_REGISTER, &CPLPFidoExampleDlg::OnBnClickedRegister)
  ON_BN_CLICKED(IDC_BTN_SIGNIN, &CPLPFidoExampleDlg::OnBnClickedSignIn)
  ON_BN_CLICKED(IDC_BTN_CLEAR, &CPLPFidoExampleDlg::OnBnClickedClear)
  ON_CBN_SELCHANGE(IDC_COMBO_DEVICE, &CPLPFidoExampleDlg::OnCbnSelchangeDevice)
  ON_BN_CLICKED(IDC_CHECK_UV, &CPLPFidoExampleDlg::OnBnClickedRequireUv)
  ON_MESSAGE(WM_APP_LOG, &CPLPFidoExampleDlg::OnAppLog)
  ON_MESSAGE(WM_APP_DONE, &CPLPFidoExampleDlg::OnAppDone)
  ON_WM_GETMINMAXINFO()
END_MESSAGE_MAP()

BOOL CPLPFidoExampleDlg::OnInitDialog()
{
  CDialogEx::OnInitDialog();

  CRect rc;
  GetWindowRect(&rc);
  m_minSize = rc.Size();

  m_logFont.CreatePointFont(100, _T("Consolas"));
  m_editLog.SetFont(&m_logFont);
  m_editLog.SetLimitText(0);

  Log(FidoDemo::IsElevated()
    ? _T("Process is elevated: direct HID access to FIDO keys is possible.")
    : _T("Process is NOT elevated: Windows blocks direct HID access to FIDO keys - use 'windows://hello' (routes USB keys via webauthn.dll too) or run as Administrator."));

  Log(CString(CA2W(("Credential store: " + m_store.Location() + "  (" + std::to_string(m_store.Count()) +
    " credential(s) loaded)").c_str(), CP_UTF8)));
  if (m_store.SkippedOnLoad() > 0)
  {
    Log(CString(CA2W(("  WARNING: " + std::to_string(m_store.SkippedOnLoad()) +
      " unreadable entries skipped").c_str(), CP_UTF8)));
  }

  OnBnClickedRefresh();
  return TRUE;
}

void CPLPFidoExampleDlg::OnCancel()
{
  // A worker thread still uses m_fido - don't tear down the dialog underneath it
  if (m_busy)
  {
    Log(_T("Operation in progress - complete or cancel it on the authenticator first (timeout 60 s)."));
    return;
  }
  CDialogEx::OnCancel();
}

void CPLPFidoExampleDlg::OnBnClickedRefresh()
{
  Log(_T("Enumerating devices ..."));
  m_devices = FidoDemo::ListDevices([this](const std::string& s) { Log(CString(CA2W(s.c_str(), CP_UTF8))); });

  m_comboDevice.ResetContent();
  for (const auto& d : m_devices)
  {
    m_comboDevice.AddString(CString(CA2W(d.label.c_str(), CP_UTF8)));
  }
  if (!m_devices.empty())
  {
    m_comboDevice.SetCurSel(0);
  }
  UpdatePinField();
}

void CPLPFidoExampleDlg::OnBnClickedInfo()
{
  std::string path = SelectedDevicePath();
  RunAsync([this, path](const FidoDemo::LogFn& log)
  {
    FidoDemo::DeviceInfo(path, log);
    return FidoResult{};  // no result dialog for device info
  });
}

void CPLPFidoExampleDlg::OnBnClickedRegister()
{
  UpdateData(TRUE);
  std::string path = SelectedDevicePath();
  std::string rpId = ToUtf8(m_rpId);
  std::string user = ToUtf8(m_userName);
  std::string pin = ToUtf8(m_pin);
  bool rk = m_discoverable != FALSE;
  bool roaming = m_roamingOnly != FALSE;
  bool uv = m_requireUv != FALSE;
  RunAsync([this, path, rpId, user, pin, rk, roaming, uv](const FidoDemo::LogFn& log)
  {
    return m_fido.Register(path, rpId, user, pin, rk, roaming, uv, log);
  });
}

void CPLPFidoExampleDlg::OnBnClickedSignIn()
{
  UpdateData(TRUE);
  std::string path = SelectedDevicePath();
  std::string rpId = ToUtf8(m_rpId);
  std::string pin = ToUtf8(m_pin);
  bool rk = m_discoverable != FALSE;
  bool roaming = m_roamingOnly != FALSE;
  bool uv = m_requireUv != FALSE;
  RunAsync([this, path, rpId, pin, rk, roaming, uv](const FidoDemo::LogFn& log)
  {
    return m_fido.SignIn(path, rpId, pin, rk, roaming, uv, log);
  });
}

void CPLPFidoExampleDlg::OnBnClickedClear()
{
  m_editLog.SetWindowText(_T(""));
}

void CPLPFidoExampleDlg::OnCbnSelchangeDevice()
{
  UpdatePinField();
}

void CPLPFidoExampleDlg::OnBnClickedRequireUv()
{
  UpdatePinField();
}

// The PIN field is only used for direct HID access with user verification required
void CPLPFidoExampleDlg::UpdatePinField()
{
  std::string path = SelectedDevicePath();
  bool enable = IsDlgButtonChecked(IDC_CHECK_UV) == BST_CHECKED && !path.empty() && path != "windows://hello";
  GetDlgItem(IDC_EDIT_PIN)->EnableWindow(enable);
}

void CPLPFidoExampleDlg::OnGetMinMaxInfo(MINMAXINFO* lpMMI)
{
  CDialogEx::OnGetMinMaxInfo(lpMMI);
  if (m_minSize.cx > 0)
  {
    lpMMI->ptMinTrackSize.x = m_minSize.cx;
    lpMMI->ptMinTrackSize.y = m_minSize.cy;
  }
}

LRESULT CPLPFidoExampleDlg::OnAppLog(WPARAM, LPARAM lParam)
{
  std::unique_ptr<CString> text(reinterpret_cast<CString*>(lParam));
  Log(*text);
  return 0;
}

LRESULT CPLPFidoExampleDlg::OnAppDone(WPARAM, LPARAM lParam)
{
  std::unique_ptr<FidoResult> result(reinterpret_cast<FidoResult*>(lParam));
  SetBusy(false);
  Log(_T(""));
  if (result && !result->title.empty())
  {
    ShowResult(*result);
  }
  return 0;
}

void CPLPFidoExampleDlg::ShowResult(const FidoResult& result)
{
  CTaskDialog dlg(CString(CA2W(result.details.c_str(), CP_UTF8)), CString(CA2W(result.title.c_str(), CP_UTF8)),
    _T("PLP FIDO Example"), TDCBF_OK_BUTTON, TDF_POSITION_RELATIVE_TO_WINDOW);
  dlg.SetMainIcon(result.ok ? TD_INFORMATION_ICON : TD_ERROR_ICON);
  dlg.DoModal(GetSafeHwnd());
}

void CPLPFidoExampleDlg::Log(const CString& text)
{
  int len = m_editLog.GetWindowTextLength();
  m_editLog.SetSel(len, len);
  m_editLog.ReplaceSel(text + _T("\r\n"));
}

FidoDemo::LogFn CPLPFidoExampleDlg::MakeThreadLogger() const
{
  HWND hwnd = GetSafeHwnd();
  return [hwnd](const std::string& s)
  {
    auto* text = new CString(CA2W(s.c_str(), CP_UTF8));
    if (!::PostMessage(hwnd, WM_APP_LOG, 0, reinterpret_cast<LPARAM>(text)))
    {
      delete text;
    }
  };
}

std::string CPLPFidoExampleDlg::SelectedDevicePath() const
{
  int sel = m_comboDevice.GetCurSel();
  if (sel < 0 || sel >= static_cast<int>(m_devices.size()))
  {
    return {};
  }
  return m_devices[sel].path;
}

std::string CPLPFidoExampleDlg::ToUtf8(const CString& s)
{
  return std::string(CW2A(s, CP_UTF8));
}

void CPLPFidoExampleDlg::RunAsync(std::function<FidoResult(const FidoDemo::LogFn&)> work)
{
  SetBusy(true);
  FidoDemo::LogFn log = MakeThreadLogger();
  HWND hwnd = GetSafeHwnd();
  std::thread([work = std::move(work), log, hwnd]()
  {
    auto* result = new FidoResult(work(log));
    if (!::PostMessage(hwnd, WM_APP_DONE, 0, reinterpret_cast<LPARAM>(result)))
    {
      delete result;
    }
  }).detach();
}

void CPLPFidoExampleDlg::SetBusy(bool busy)
{
  m_busy = busy;
  for (int id : { IDC_COMBO_DEVICE, IDC_BTN_REFRESH, IDC_BTN_INFO, IDC_BTN_REGISTER, IDC_BTN_SIGNIN })
  {
    GetDlgItem(id)->EnableWindow(!busy);
  }
}
