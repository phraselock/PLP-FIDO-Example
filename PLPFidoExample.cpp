#include "framework.h"
#include "PLPFidoExample.h"
#include "PLPFidoExampleDlg.h"
#include "FidoDemo.h"

#pragma comment(lib, "gdiplus.lib")

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

  // GDI+ draws the logo; it must outlive the dialog, which owns the logo bitmap
  Gdiplus::GdiplusStartupInput gdiplusInput;
  ULONG_PTR gdiplusToken = 0;
  Gdiplus::GdiplusStartup(&gdiplusToken, &gdiplusInput, nullptr);
  {
    CPLPFidoExampleDlg dlg;
    m_pMainWnd = &dlg;
    dlg.DoModal();
    m_pMainWnd = nullptr;
  }
  Gdiplus::GdiplusShutdown(gdiplusToken);

  return FALSE;
}
