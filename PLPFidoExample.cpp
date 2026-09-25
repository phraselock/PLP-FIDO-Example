#include "framework.h"
#include "PLPFidoExample.h"
#include "PLPFidoExampleDlg.h"
#include "FidoDemo.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

BEGIN_MESSAGE_MAP(CPLPFidoExampleApp, CWinApp)
END_MESSAGE_MAP()

CPLPFidoExampleApp::CPLPFidoExampleApp()
{
}

CPLPFidoExampleApp theApp;

BOOL CPLPFidoExampleApp::InitInstance()
{
  INITCOMMONCONTROLSEX icc{ sizeof(icc), ICC_WIN95_CLASSES };
  InitCommonControlsEx(&icc);

  CWinApp::InitInstance();

  // Must be called once before any other libfido2 function
  FidoDemo::Init();

  CPLPFidoExampleDlg dlg;
  m_pMainWnd = &dlg;
  dlg.DoModal();

  return FALSE;
}
