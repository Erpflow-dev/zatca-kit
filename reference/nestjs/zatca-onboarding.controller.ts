import {
  BadGatewayException,
  BadRequestException,
  Body,
  ConflictException,
  Controller,
  Get,
  HttpCode,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import { Type } from 'class-transformer';
import {
  ArrayMinSize,
  IsArray,
  IsString,
  IsUUID,
  Length,
  Matches,
  ValidateNested,
} from 'class-validator';
import {
  AdminRequest,
  AdminTokenGuard,
} from '../../common/guards/admin-token.guard';
import {
  FatooraOnboardingService,
  OnboardingError,
} from './fatoora-onboarding.service';

class OnboardCsrDto {
  /** base64 of the PEM CSR — the exact body POST /compliance forwards. */
  @IsString() @Length(1, 20000) csr: string;
  /**
   * Fatoora-portal OTP, 1-hour validity. Sandbox magic values: 123345 =
   * valid, 111111 = invalid, 222222 = expired (docs/10).
   */
  @IsString() @Matches(/^\d{6}$/, { message: 'otp must be 6 digits' })
  otp: string;
}

class ComplianceCheckInvoiceDto {
  /** base64 SHA-256 of the canonicalized XML. */
  @IsString() @Length(1, 128) invoiceHash: string;
  @IsUUID() uuid: string;
  /** base64 of the signed UBL XML. */
  @IsString() @Length(1, 4_000_000) invoice: string;
}

class RunChecksDto {
  @IsArray()
  @ArrayMinSize(1)
  @ValidateNested({ each: true })
  @Type(() => ComplianceCheckInvoiceDto)
  invoices: ComplianceCheckInvoiceDto[];
}

/**
 * Tenant-admin surface for the CSID onboarding chain (docs/10): compliance
 * CSID → compliance checks → production CSID, renewal, and the status the
 * fleet view reads. Session-token auth like every /admin route.
 */
@Controller('admin/zatca')
@UseGuards(AdminTokenGuard)
export class ZatcaOnboardingController {
  constructor(private readonly onboarding: FatooraOnboardingService) {}

  /** Maps onboarding domain errors to HTTP (mirrors AdminController.run). */
  private async run<T>(fn: () => Promise<T>): Promise<T> {
    try {
      return await fn();
    } catch (err) {
      if (err instanceof OnboardingError) {
        if (err.httpStatus === 409) throw new ConflictException(err.message);
        if (err.httpStatus >= 500) throw new BadGatewayException(err.message);
        throw new BadRequestException(err.message);
      }
      throw err;
    }
  }

  @Post('onboarding/compliance')
  compliance(@Req() req: AdminRequest, @Body() dto: OnboardCsrDto) {
    return this.run(() =>
      this.onboarding.requestComplianceCsid(req.admin.tenantId, dto.csr, dto.otp),
    );
  }

  @Post('onboarding/checks')
  @HttpCode(200)
  checks(@Req() req: AdminRequest, @Body() dto: RunChecksDto) {
    return this.run(() =>
      this.onboarding.runComplianceChecks(req.admin.tenantId, dto.invoices),
    );
  }

  @Post('onboarding/production')
  production(@Req() req: AdminRequest) {
    return this.run(() =>
      this.onboarding.requestProductionCsid(req.admin.tenantId),
    );
  }

  @Post('onboarding/renew')
  renew(@Req() req: AdminRequest, @Body() dto: OnboardCsrDto) {
    return this.run(() =>
      this.onboarding.renewProductionCsid(req.admin.tenantId, dto.csr, dto.otp),
    );
  }

  @Get('status')
  status(@Req() req: AdminRequest) {
    return this.onboarding.status(req.admin.tenantId);
  }
}
