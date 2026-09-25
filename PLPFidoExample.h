#pragma once

#ifndef __AFXWIN_H__
#error "include 'framework.h' before including this file for PCH"
#endif

#include "resource.h"

class CPLPFidoExampleApp : public CWinApp
{
public:
  CPLPFidoExampleApp();

  BOOL InitInstance() override;

  DECLARE_MESSAGE_MAP()
};

extern CPLPFidoExampleApp theApp;
