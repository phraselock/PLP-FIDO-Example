#pragma once

#include <functional>
#include <vector>

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
  void OnCancel() override;

  afx_msg void OnBnClickedRefresh();
  afx_msg void OnBnClickedInfo();
  afx_msg void OnBnClickedRegister();
  afx_msg void OnBnClickedSignIn();
  afx_msg void OnBnClickedClear();
  afx_msg LRESULT OnAppLog(WPARAM wParam, LPARAM lParam);
  afx_msg LRESULT OnAppDone(WPARAM wParam, LPARAM lParam);
  DECLARE_MESSAGE_MAP()

private:
  // Posted from worker threads; lParam of WM_APP_LOG is a heap-allocated CString* owned by the receiver
  static constexpr UINT WM_APP_LOG = WM_APP + 1;
  static constexpr UINT WM_APP_DONE = WM_APP + 2;

  void Log(const CString& text);
  FidoDemo::LogFn MakeThreadLogger() const;
  std::string SelectedDevicePath() const;
  static std::string ToUtf8(const CString& s);

  // Runs a (blocking) libfido2 operation on a worker thread and keeps the UI responsive
  void RunAsync(std::function<void(const FidoDemo::LogFn&)> work);
  void SetBusy(bool busy);

  CComboBox m_comboDevice;
  CEdit m_editLog;
  CString m_rpId;
  CString m_userName;
  CString m_pin;
  BOOL m_discoverable = FALSE;
  BOOL m_roamingOnly = TRUE;
  CFont m_logFont;

  std::vector<FidoDevice> m_devices;
  FidoDemo m_fido;
  bool m_busy = false;
};
