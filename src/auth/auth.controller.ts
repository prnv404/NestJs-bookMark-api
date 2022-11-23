import { Body, Controller, Post, Req } from '@nestjs/common';
import { AuthService } from './auth.service';
import { authDto } from './dto';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('signup')
  signup(@Body() dto: authDto) {
    
    return this.authService.signup(dto)
  }

  @Post('signin')
  signin(@Body() dto:authDto) {
    return this.authService.signin(dto)
  }
}
