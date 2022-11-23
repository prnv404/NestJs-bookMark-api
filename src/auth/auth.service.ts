import { ForbiddenException, HttpException, Injectable } from '@nestjs/common';
import { User, Bookmark } from '@prisma/client';
import { PrismaService } from 'src/prisma/prisma.service';
import { authDto } from './dto';
import * as argon from 'argon2';
import { JwtService } from '@nestjs/jwt';
@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService, private jwt: JwtService) {}

  async signup(dto: authDto) {
    //   generate password
    const hash = await argon.hash(dto.password);
    // save the new user in the db
    const user = await this.prisma.user.create({
      data: {
        email: dto.email,
        hash,
        firstname: dto.firstname,
        lastname: dto.lastname,
      },
    });
    //   return the saved user
    delete user.hash;
    return this.signToken(user.id, user.email);
  }

  async signin(dto: authDto) {
    // find user by email
    const user = await this.prisma.user.findFirst({
      where: {
        email: dto.email,
      },
    });
    // if user dosent exist throw execption
    if (!user) {
      throw new ForbiddenException('No user found');
    }
    // compare password
    const passwordMatch = await argon.verify(user.hash, dto.password);
    // if password incorrect throw exception
    if (!passwordMatch) {
      throw new ForbiddenException('password doesent match');
    }
    // send back the user
    delete user.hash;
    return this.signToken(user.id, user.email);
  }

  async signToken(userId: number, email: string): Promise<{ access_token: string }> {
    const data = {
      sub: userId,
      email,
    };
    const token = await this.jwt.signAsync(data, {
      expiresIn: '10m',
      secret: process.env.JWT_SECRET,
    });
    return { access_token: token };
  }
}
