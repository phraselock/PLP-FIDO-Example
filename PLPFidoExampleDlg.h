#pragma once

#include <functional>
#include <vector>

#include "CredentialStore.h"
#include "FidoDemo.h"

class CPLPFidoExampleDlg : public CDialogEx
{
public:
  CPLPFidoExampleDlg(CWnd* pParent = nullptr);

#ifdef AFX_DESIGN_TIME
  enum { IDD = IDD_PLPFIDOEXAMPLE_DIALOG };
#endif

protected:
  void DoDataExchange(CDataExchange* pDX) override;
  BOOL OnInitDialog() override;
  void OnOK() override;
  void OnCancel() override;

  afx_msg void OnBnClickedRefresh();
  afx_msg void OnBnClickedInfo();
  afx_msg void OnBnClickedRegister();
  afx_msg void OnBnClickedSignIn();
  afx_msg void OnBnClickedClear();
  afx_msg void OnCbnSelchangeDevice();
  afx_msg void OnBnClickedRequireUv();
  afx_msg LRESULT OnAppLog(WPARAM wParam, LPARAM lParam);
  afx_msg LRESULT OnAppDone(WPARAM wParam, LPARAM lParam);
  afx_msg void OnGetMinMaxInfo(MINMAXINFO* lpMMI);
  DECLARE_MESSAGE_MAP()

private:
  // Posted from worker threads; lParam is heap-allocated and owned by the receiver:
  // WM_APP_LOG -> CString*, WM_APP_DONE -> FidoResult*
  static constexpr UINT WM_APP_LOG = WM_APP + 1;
  static constexpr UINT WM_APP_DONE = WM_APP + 2;

  void Log(const CString& text);
  FidoDemo::LogFn MakeThreadLogger() const;
  std::string SelectedDevicePath() const;
  void UpdatePinField();
  static std::string ToUtf8(const CString& s);

  // Runs a (blocking) libfido2 operation on a worker thread and keeps the UI responsive
  void RunAsync(std::function<FidoResult(const FidoDemo::LogFn&)> work);
  void ShowResult(const FidoResult& result);
  void SetBusy(bool busy);

  CComboBox m_comboDevice;
  CEdit m_editLog;
  CString m_rpId;
  CString m_userName;
  CString m_pin;
  BOOL m_discoverable = FALSE;
  BOOL m_roamingOnly = TRUE;
  BOOL m_requireUv = FALSE;
  CFont m_logFont;
  CSize m_minSize;  // initial window size = minimum when resizing

  std::vector<FidoDevice> m_devices;
  CredentialStore m_store;  // declared before m_fido, which keeps a reference to it
  FidoDemo m_fido;
  bool m_busy = false;
};
